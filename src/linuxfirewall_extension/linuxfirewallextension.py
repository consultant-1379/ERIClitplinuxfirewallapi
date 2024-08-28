##############################################################################
# COPYRIGHT Ericsson AB 2013
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

from litp.core.model_type import ItemType, Property, PropertyType, Collection
from litp.core.extension import ModelExtension
from litp.core.validators import ItemValidator, PropertyValidator, \
                                 ValidationError, PropertyLengthValidator
from netaddr import IPAddress, AddrFormatError, AddrConversionError

from litp.core.litp_logging import LitpLogger
from litp.core.translator import Translator

log = LitpLogger()

t = Translator('ERIClitplinuxfirewallapi_CXP9031106')
_ = t._


class ListLengthValidator(PropertyValidator):
    """
    Validates that a comma seperate list is less than a specified limit.
    """

    def __init__(self, length_limit):
        """
        Validates that a list's length doesn't exceed a specified limit.

        :param length_limit: limit on number of elements in list.
        :type  lenght_limit: int

        :returns: None or ValidatonError

        """
        super(ListLengthValidator, self).__init__()
        self.length_limit = length_limit
        self.list_separator = ','

    def validate(self, property_value):
        """
        Validate the property
        :param property_value: value to validate
        :type  property_value: string

        """
        items = []
        if self.list_separator in property_value:
            items = property_value.split(self.list_separator)
        if not len(items) <= self.length_limit:
            msg = _("MAX_NUMBER_OF_N_PORTS_ACCEPTED") % self.length_limit
            err = ValidationError(error_message=msg)
            return err


class IPAddressRangeValidator(PropertyValidator):
    """
    Validates a range IP range.

    Ensures that the start of the range is not after the end and \
that the start and end are valid ip addresses.
    """

    def validate(self, property_value):
        if '-' in property_value:
            if '!' in property_value:
                emsg = (_("IP_RANGE_NEGATION_NOT_SUPPORTED"))
                return ValidationError(error_message=emsg)

            start_prop = property_value.split('-')[0].replace(' ', '')
            end_prop = property_value.split('-')[1].replace(' ', '')

            try:
                range_start = IPAddress(start_prop)
                range_end = IPAddress(end_prop)
            except (AddrConversionError, AddrFormatError, ValueError,
                    UnboundLocalError, TypeError):
                # UnboundLocalError required here
                # until >= netaddr-0.7.6 is used
                emsg = _("INVALID_RANGE_VALUE") % property_value
                return ValidationError(error_message=emsg)

            if range_start > range_end:
                str_range_start = str(range_start)
                str_range_end = str(range_end)
                msg = (_("INVALID_RANGE_VALUE_N_MUST_BE_BEFORE_M")
                       % (str_range_start, str_range_end))
                return ValidationError(error_message=msg)


class ReservedChainValuesValidator(PropertyValidator):
    """
    Validates that reserved chain values are not supplied.
    """

    def __init__(self, reserved_chain_values):
        """
        Restricts the revserved property values.

        :param reserved_chain_values: Restricted property values.
        :type  reserved_chain_values: list

        :returns: None or ValidatonError

        """
        super(ReservedChainValuesValidator, self).__init__()
        self.reserved_chain_values = reserved_chain_values

    def validate(self, property_value):
        chain_value = [x for x in property_value.split() if x.isdigit()]
        if chain_value and chain_value[0] in self.reserved_chain_values:
            msg = (_("S_IS_RESERVED_CHAIN_NUMBER_FOR_DEFAULT_RULES") %
                   chain_value[0])
            err = ValidationError(error_message=msg)
            return err


class DeprecatedChainNumberValidator(PropertyValidator):
    """
    Validates that chain numbers are between 0 and 999.
    """

    def validate(self, property_value):
        chain_value = [x for x in property_value.split() if x.isdigit()]
        if int(chain_value[0]) > 999:
            log.trace.warning(
                "'%s' is a deprecated chain number." % chain_value[0])


class ValidationOfTosourceParameterConstraints(ItemValidator):
    """
    Validates the required combination of parameters are set \
    for firewall rules with tosource property.

    :param property_value: value to validate
    :type  property_value: string

    Checks provided include:

    - if jump is 'SNAT', table must be 'nat'

    - if jump is 'SNAT', chain must be 'POSTROUTING'

    - if jump is 'SNAT', tosource property must be supplied

    - tosource must be set to a valid IPv4 address

    - when the tosource property is set, provider must be set to 'iptables'

    :returns: None or ValidatonError
    """

    def validate(self, properties):
        table_prop = properties.get('table', None)
        jump_prop = properties.get('jump', None)
        chain_prop = properties.get('chain', None)
        tosource_prop = properties.get('tosource', None)
        provider_prop = properties.get('provider', None)
        protocol_prop = properties.get('proto', None)

        error = None

        if tosource_prop:

            if 'iptables' != provider_prop:
                msg = (_("PROPERTY_NOT_SUPPORTED"))
                error = ValidationError(error_message=msg,
                                        property_name='provider')

            elif 'SNAT' == jump_prop and 'nat' != table_prop:
                msg = (_("INVALID_PROPERTY_COMBINATION")) % \
                        ('table', 'nat', 'jump', jump_prop)
                error = ValidationError(error_message=msg,
                                        property_name='jump')

            elif 'SNAT' != jump_prop:
                msg = (_("INVALID_PROPERTY_WHEN_USING")) % \
                        ('jump', 'tosource', tosource_prop)
                error = ValidationError(error_message=msg,
                                        property_name='jump')

            elif 'SNAT' == jump_prop and 'POSTROUTING' != chain_prop:
                msg = (_("INVALID_PROPERTY_COMBINATION")) % \
                        ('chain', 'POSTROUTING', 'jump', jump_prop)
                error = ValidationError(error_message=msg,
                                        property_name='jump')

            else:
                v4_rule = jump_prop == 'SNAT' and \
                          table_prop == 'nat' and \
                          chain_prop == 'POSTROUTING' and \
                          protocol_prop in ('udp', 'tcp')

                if not v4_rule:
                    msg = (_("INVALID_ALL_PROPERTY_COMBINATION"))
                    error = ValidationError(error_message=msg,
                                            property_name='tosource')

        elif not tosource_prop and 'SNAT' == jump_prop:
            msg = (_("MISSING_TOSOURCE_PROPERTY"))
            error = ValidationError(error_message=msg,
                                    property_name='jump')

        return error


class ValidationPortStateNone(ItemValidator):
    """
    Validates that one of either dport and sport must be
    set when state 'none' is used.
    """

    def validate(self, properties):

        dport_prop = properties.get('dport', None)
        sport_prop = properties.get('sport', None)
        state_prop = properties.get('state', None)

        error = None

        if (not dport_prop and not sport_prop) and state_prop == 'none':
            msg = _("STATE_NONE_WITHOUT_PORT")
            error = ValidationError(error_message=msg)

        return error


class ValidationOfStringAlgoConstraints(ItemValidator):
    """
    Validates the required combination of parameters are set \
    for firewall rules with string property.

    :param property_value: value to validate
    :type  property_value: string

    Checks provided include:

    - if string less than or equal to 128 characters

    - if string is set, algo must be set

    - if algo is set, string must be set

    :returns: None or ValidatonError
    """

    def validate(self, properties):

        algo_prop = properties.get('algo', None)
        string_prop = properties.get('string', None)

        error = None

        if string_prop and not algo_prop:
            msg = (_("DEPENDENT_PROPERTIES")) % ('algo', 'string')
            error = ValidationError(error_message=msg,
                                    property_name='algo')

        if algo_prop and not string_prop:
            msg = (_("DEPENDENT_PROPERTIES")) % ('string', 'algo')
            error = ValidationError(error_message=msg,
                                    property_name='string')

        return error


class SourceDestinationValidator(ItemValidator):
    """
    Validates that the provider, source and destination properties \
    do not contain an invalid combination of IPv4 and IPv6 addresses.
    """

    def validate(self, properties):
        provider = 'provider'
        no_provider = 'no provider'
        source = 'source'
        destination = 'destination'
        src_or_dest = 'source / destination'
        iptables = 'iptables'
        ip6tables = 'ip6tables'
        ipv4_address = 'an IPv4 address'
        ipv6_address = 'an IPv6 address'
        msg_template = ("Invalid combination of %s and %s "
                        "for the '%s' and '%s' properties.")
        error = None
        provider_prop = properties.get(provider, '')
        source_prop = properties.get(source, '')
        dest_prop = properties.get(destination, '')
        if iptables in provider_prop and ':' in source_prop:
            msg = msg_template % (iptables, ipv6_address,
                                  provider, source)
            error = ValidationError(error_message=msg)
        elif iptables in provider_prop and ':' in dest_prop:
            msg = msg_template % (iptables, ipv6_address,
                                  provider, destination)
            error = ValidationError(error_message=msg)
        elif ip6tables in provider_prop and '.' in source_prop:
            msg = msg_template % (ip6tables, ipv4_address,
                                  provider, source)
            error = ValidationError(error_message=msg)
        elif ip6tables in provider_prop and '.' in dest_prop:
            msg = msg_template % (ip6tables, ipv4_address,
                                  provider, destination)
            error = ValidationError(error_message=msg)
        elif '.' in source_prop and ':' in dest_prop:
            msg = msg_template % (ipv4_address, ipv6_address,
                                  source, destination)
            error = ValidationError(error_message=msg)
        elif ':' in source_prop and '.' in dest_prop:
            msg = msg_template % (ipv6_address, ipv4_address,
                                  destination, source)
            error = ValidationError(error_message=msg)
        elif ((':' in source_prop or ':' in dest_prop)
               and ip6tables not in provider_prop):
            msg = msg_template % (no_provider, ipv6_address,
                                  provider, src_or_dest)
            msg += (" (Please set provider to '%s')"
                    % ip6tables)
            error = ValidationError(error_message=msg)
        elif (('.' in source_prop or '.' in dest_prop)
               and iptables not in provider_prop):
            msg = msg_template % (no_provider, ipv4_address,
                                  provider, src_or_dest)
            msg += (" (Please set provider to '%s')"
                    % iptables)
            error = ValidationError(error_message=msg)
        return error


class LinuxFirewallExtension(ModelExtension):
    """
    Allows for the modelling of 'firewall-node-config', \
'firewall-cluster-config' and 'firewall-rule' items.
    The LITP linux firewall Plugin provides configuration \
for iptables and ip6tables based on these model items.
    """

    def define_property_types(self):
        reserved_chains = [
            '988', '989', '990', '991', '992', '993', '994',
            '995', '996', '997', '998', '999'
        ]
        property_types = []
        property_types.append(PropertyType("firewall_rule_name",
            regex=r"^(([0-9]+ [A-Za-z0-9 ]+)|([0-9]+))$",
            validators=[ReservedChainValuesValidator(reserved_chains),
                        DeprecatedChainNumberValidator(),
                        PropertyLengthValidator(255)]))
        property_types.append(PropertyType("firewall_rule_proto",
                                    regex=r"^(tcp|udp|icmp|ipv6-icmp|esp|ah|"\
                                          "vrrp|igmp|ipencap|ospf|gre|all)$"))
        property_types.append(PropertyType("firewall_rule_action",
                                           regex=r"^(accept|drop|reject)$",
                                           regex_error_desc="Property must be"
                                           " either 'accept', 'drop'"
                                           " or 'reject'"))
        property_types.append(PropertyType(
            "firewall_rule_port",
            regex=(r"^(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|"
                r"[1-5][0-9]{4}|[1-9][0-9]{1,3}|[0-9])((,|-)(6553[0-5]|"
                r"655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|"
                r"[1-9][0-9]{1,3}|[0-9]))*$"),
            validators=[ListLengthValidator(15)])
        )
        property_types.append(PropertyType("firewall_rule_state",
                regex=r"^(none|NEW|ESTABLISHED|RELATED|INVALID|NEW,"
                      "ESTABLISHED,RELATED|ESTABLISHED,RELATED|RELATED,"
                      "ESTABLISHED)$"))
        property_types.append(PropertyType("firewall_rule_ip_range",
                                  regex=r"^[0-9a-fA-F.:/-]+$",
                                  validators=[IPAddressRangeValidator()]))
        property_types.append(PropertyType("firewall_rule_ip_range_src",
                                  regex=r"^!{0,1}\s*[0-9a-fA-F.:/-]+$",
                                  validators=[IPAddressRangeValidator()]))
        property_types.append(PropertyType("firewall_rule_icmp",
                regex=r"^([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-4]|"
                      r"echo-reply|echo-request)$"))
        property_types.append(PropertyType("firewall_rule_chain",
                regex=r"^(INPUT|OUTPUT|FORWARD|PREROUTING|POSTROUTING)$"))
        property_types.append(PropertyType("firewall_rule_provider",
                                           regex=r"^(iptables|ip6tables)$"))
        property_types.append(PropertyType("firewall_rule_log_level",
            regex=r"^(panic|alert|crit|err|warn|warning|notice|info|debug)$"))
        property_types.append(PropertyType("firewall_rule_string",
                                           regex=r"^[A-Za-z_]+$"))
        property_types.append(PropertyType("firewall_rule_table",
            regex=r"^(nat|filter|mangle|raw)$"))
        property_types.append(PropertyType("firewall_rule_setdscp",
                                           regex=r"^0[xX][0-9a-fA-F]+$"))
        property_types.append(PropertyType("firewall_rule_limit",
            regex=r"^([0-9]+/sec|[0-9]+/min|[0-9]+/hour|[0-9]+/day)$"))
        property_types.append(PropertyType("firewall_rule_algo",
                                           regex=r"^(kmp|bm)$",
                                           regex_error_desc="Property must"
                                           " be 'kmp' or 'bm'."))
        property_types.append(PropertyType("firewall_rule_match_string",
                                           regex=r'^.{1,128}$',
                                           regex_error_desc="Property must"
                                           " be 1-128 characters in length."))
        return property_types

    def define_item_types(self):
        item_types = []
        item_types.append(
          ItemType("firewall-node-config",
                   extend_item="node-config",
                   item_description="A node level firewall configuration."
                   " firewall-node-config and "
                   "  :doc:`firewall_cluster_config "
                   "<../item_types/firewall_cluster_config>`"
                   " items cannot have conflicting drop_all values.",
                   drop_all=Property("basic_boolean",
                                     default="true",
                                     prop_description='Add the drop rule '
                                     '(drop all traffic not explicitly'
                                     ' allowed) for iptables/ip6tables'),
                   rules=Collection("firewall-rule"))
        )
        item_types.append(
          ItemType("firewall-cluster-config",
                   extend_item="cluster-config",
                   item_description="A cluster level firewall configuration."
                   "  :doc:`firewall_node_config "
                   "<../item_types/firewall_node_config>` "
                   " and firewall-cluster-config model"
                   " items cannot have conflicting drop_all values.",
                   drop_all=Property("basic_boolean",
                                     default="true",
                                     prop_description='Add the drop rule for'
                                                      ' iptables/ip6tables'),
                   rules=Collection("firewall-rule"))
        )
        item_types.append(
          ItemType("firewall-rule",
                   item_description="A firewall rule. Validation does "
                                    "not check for "
                                    "the misuse of combinations "
                                    "of properties.",
                   validators=[SourceDestinationValidator(),
                               ValidationOfTosourceParameterConstraints(),
                               ValidationOfStringAlgoConstraints(),
                               ValidationPortStateNone()],
                   name=Property("firewall_rule_name",
                          prop_description="The name of the firewall rule. "
                          "This value must be unique.", required=True),
                   proto=Property("firewall_rule_proto",
                           updatable_plugin=True,
                           prop_description="The protocol. The default value"
                           " is ``tcp`` for ports."),
                   action=Property("firewall_rule_action",
                            updatable_plugin=True,
                            prop_description="Whether the packet is accepted "
                            "``(accept)``, dropped ``(drop)`` or"
                            " rejected ``(reject)``. "
                            " The default value is ``accept`` "
                            "unless a value for the jump property has "
                            "been specified."),
                   sport=Property("firewall_rule_port",
                           prop_description="The source port. "
                           "This can be a single value, a list of "
                           "comma-separated values (max. 15 ports) or a range."
                           ),
                   dport=Property("firewall_rule_port",
                           prop_description="The destination port. "
                           "This can be a single value, a list of "
                           "comma-separated values (max. 15 ports) or a range."
                           ),
                   state=Property("firewall_rule_state",
                           updatable_plugin=True,
                           prop_description="The packet state. This can be a "
                           "single value or list of comma-separated values. "
                           "The default value is ``NEW`` for ports."),
                   source=Property("firewall_rule_ip_range_src",
                            prop_description="The source address of the "
                            "packets. This can be an IP address, IP address "
                            "subnet or IP address range."),
                   tosource=Property("ipv4_address",
                            prop_description="Specifies which source the"
                            " packet should use. When setting jump as 'SNAT',"
                            " specify the new source address using"
                            " this parameter."),
                   destination=Property("firewall_rule_ip_range",
                                 prop_description="The destination address to"
                                 " which the rule is applied."
                                 " This can be an IP address, "
                                 "IP address subnet or IP address range."),
                   iniface=Property("basic_string",
                             prop_description="The incoming interface to "
                             "which the rule is applied."),
                   outiface=Property("basic_string",
                              prop_description="The outgoing interface to "
                              "which the rule is applied."),
                   icmp=Property("firewall_rule_icmp",
                          prop_description="The icmp type."),
                   chain=Property("firewall_rule_chain",
                           prop_description="The chain to which the rule is "
                           "applied. "
                           "If this parameter is not included, the rule is "
                           "applied to ``INPUT`` and "
                           "``OUTPUT`` chains."),
                   provider=Property("firewall_rule_provider",
                              prop_description="Specifies the iptables or "
                              "ip6tables to which the rule applies. If this "
                              "parameter is not included, the rule is applied "
                              "to iptables and ip6tables."),
                   limit=Property("firewall_rule_limit",
                           prop_description="The maximum average matching"
                           " rate. This value can include an optional "
                           "``/sec``, ``/min``, ``/hour``, or ``/day`` "
                           "suffix."),
                   log_level=Property("firewall_rule_log_level",
                               prop_description="The logging level for log "
                               "rules."),
                   log_prefix=Property("firewall_rule_string",
                                prop_description="The log prefix with which "
                                "packets are logged. "),
                   jump=Property("firewall_rule_string",
                          prop_description="The chain to which the packet is"
                          " redirected."),
                   table=Property("firewall_rule_table",
                           prop_description="The table to which to add the "
                           "rule."),
                   toports=Property("firewall_rule_port",
                             prop_description="The ports to which to redirect."
                             " This is used with ``jump=REDIRECT``."),
                   setdscp=Property("firewall_rule_setdscp",
                             prop_description="The hex value to which to alter"
                             " the DSCP bits within the TOS (type of service) "
                             "header. This is used with ``jump=DSCP``."),
                   algo=Property("firewall_rule_algo",
                                 prop_description="The algorithim used to "
                                                  "match the string. "
                                                  "Only supported for IPv4."),
                   string=Property("firewall_rule_match_string",
                                   prop_description="The string to match "
                                                    "the packet against. "
                                                    "Only supported for IPv4.")
                   )
        )
        return item_types
