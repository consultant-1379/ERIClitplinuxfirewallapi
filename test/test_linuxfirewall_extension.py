##############################################################################
# COPYRIGHT Ericsson AB 2013
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################


import unittest
from linuxfirewall_extension.linuxfirewallextension import \
       LinuxFirewallExtension, SourceDestinationValidator, \
       ListLengthValidator, ReservedChainValuesValidator, \
       IPAddressRangeValidator, PropertyLengthValidator, \
       ValidationOfStringAlgoConstraints
from litp.core.validators import ValidationError
from litp.core.translator import Translator
from litp.core.model_manager import ModelManager
t = Translator('ERIClitplinuxfirewallapi_CXP9031106')
_ = t._


class TestLinuxFirewallExtension(unittest.TestCase):

    def setUp(self):
        self.model_manager = ModelManager()
        self.validator = self.model_manager.validator

        self.ext = LinuxFirewallExtension()

        self.prop_types = {}
        for prop_type in self.ext.define_property_types():
           self.prop_types[prop_type.property_type_id] = prop_type

    def test_property_types_registered(self):
        prop_types_expected = [
                               'firewall_rule_name', 'firewall_rule_proto',
                               'firewall_rule_action', 'firewall_rule_port',
                               'firewall_rule_state', 'firewall_rule_ip_range',
                               'firewall_rule_ip_range_src','firewall_rule_icmp',
                               'firewall_rule_chain',
                               'firewall_rule_provider',
                               'firewall_rule_log_level',
                               'firewall_rule_string', 'firewall_rule_table',
                               'firewall_rule_setdscp',
                               'firewall_rule_limit',
                               'firewall_rule_algo',
                               'firewall_rule_match_string']
        prop_types = [pt.property_type_id for pt in
                      self.ext.define_property_types()]
        self.assertEquals(prop_types_expected, prop_types)

    def test_item_types_registered(self):
        item_types_expected = ['firewall-node-config',
                               'firewall-cluster-config',
                               'firewall-rule']
        item_types = [it.item_type_id for it in
                      self.ext.define_item_types()]
        self.assertEquals(item_types_expected, item_types)

    def test_firewall_rule_type_properties(self):
        properties_expected = ['log_prefix', 'log_level', 'name', 'chain',
                               'proto', 'dport', 'destination', 'setdscp',
                               'toports', 'jump', 'source', 'outiface',
                               'state', 'sport', 'iniface', 'provider',
                               'action', 'table', 'icmp', 'limit', 'tosource',
                               'algo', 'string']
        firewall_rule_type = [it for it in self.ext.define_item_types()
                              if it.item_type_id == "firewall-rule"][0]
        firewall_rule_properties = firewall_rule_type.structure.keys()
        self.assertEquals(
            set(properties_expected), set(firewall_rule_properties))

    def test_source_destination_validator_all_error(self):
        validation_cases = [
            {"props": {"provider": "iptables",
                       "source": "fefe:fefe:fefe:fefe"},
             "error": "Invalid combination of iptables and an IPv6 address "
                      "for the 'provider' and 'source' properties."},
            {"props": {"provider": "iptables",
                       "destination": "fefe:fefe:fefe:fefe"},
             "error": "Invalid combination of iptables and an IPv6 address "
                      "for the 'provider' and 'destination' properties."},
            {"props": {"provider": "ip6tables",
                       "source": "10.10.10.10"},
             "error": "Invalid combination of ip6tables and an IPv4 address "
                      "for the 'provider' and 'source' properties."},
            {"props": {"provider": "ip6tables",
                       "destination": "10.10.10.10"},
             "error": "Invalid combination of ip6tables and an IPv4 address "
                      "for the 'provider' and 'destination' properties."},
            {"props": {"source": "1.1.1.1",
                       "destination": "fefe:fefe:fefe:fefe"},
             "error": "Invalid combination of an IPv4 address and an "
                      "IPv6 address for the 'source' and 'destination' "
                      "properties."},
            {"props": {"destination": "1.1.1.1",
                       "source": "fefe:fefe:fefe:fefe"},
             "error": "Invalid combination of an IPv6 address and an "
                      "IPv4 address for the 'destination' and 'source' "
                      "properties."},
            {"props": {"source": "10.10.10.10"},
             "error": "Invalid combination of no provider and an IPv4 address "
                      "for the 'provider' and 'source / destination' properties. "
                      "(Please set provider to 'iptables')"},
            {"props": {"source": "fefe:fefe:fefe:fefe"},
             "error": "Invalid combination of no provider and an IPv6 address "
                      "for the 'provider' and 'source / destination' properties. "
                      "(Please set provider to 'ip6tables')"},
        ]
        for case in validation_cases:
            self._src_dest_validator_error(case["props"], case["error"])

    def _src_dest_validator_error(self, props, error):
        validator = SourceDestinationValidator()
        expected = ValidationError(error_message=error)
        result = validator.validate(props)
        self.assertEqual(expected, result)

    def test_source_destination_validator_without_error(self):
        validator = SourceDestinationValidator()
        result = validator.validate({})
        self.assertEqual(None, result)

    def test_list_length_validator_with_error(self):
        validator = ListLengthValidator(15)
        result = validator.validate("1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16")
        err_str = (_('MAX_NUMBER_OF_N_PORTS_ACCEPTED') %"15")
        self.assertEqual(err_str, result.error_message)

    def test_reserved_chain_validator_with_error(self):
        validator = ReservedChainValuesValidator("123")
        result = validator.validate("123 test1")
        err_str = _('S_IS_RESERVED_CHAIN_NUMBER_FOR_DEFAULT_RULES') % "123"
        self.assertEqual(err_str, result.error_message)

    def test_ip_address_range_validator_with_invalid_prop_error(self):
        validator = IPAddressRangeValidator()
        result = validator.validate("ff:-ff:")
        err_str = _('INVALID_RANGE_VALUE') % "ff:-ff:"
        self.assertEqual(err_str, result.error_message)

    def test_ip_address_range_validator_with_invalid_range(self):
        validator = IPAddressRangeValidator()
        result = validator.validate("10.10.10.11-10.10.10.10")
        err_str =( _('INVALID_RANGE_VALUE_N_MUST_BE_BEFORE_M') % ("10.10.10.11","10.10.10.10" ))
        self.assertEqual(err_str, result.error_message)

    def test_rule_name_length_validator(self):
        length = 10
        validator = PropertyLengthValidator(length)
        result = validator.validate("12345678911")
        err_str = ('Property cannot be longer than %s' % (length))
        self.assertEqual(err_str, result.error_message)

    def test_rule_string_algo_validator(self):
        validator = ValidationOfStringAlgoConstraints()
        algo_prop = 'kmp'
        string_prop = 'teststring'

        result = validator.validate({'string': string_prop, 'algo': algo_prop})
        self.assertEqual(None, result)

        result = validator.validate({'string': string_prop})
        msg = (_("DEPENDENT_PROPERTIES")) % ('algo', 'string')
        error = ValidationError(error_message=msg, property_name='algo')
        self.assertEqual(error, result)

        result = validator.validate({'algo': algo_prop})
        msg = (_("DEPENDENT_PROPERTIES")) % ('string', 'algo')
        error = ValidationError(error_message=msg, property_name='string')
        self.assertEqual(error, result)

    def test_icmp_types(self):
        def _assert_no_error(self, prop_type, value):
            self.assertEquals([],
             self.validator._run_property_type_validators(prop_type,
                                                          'firewall_rule_icmp',
                                                          value))
        def _assert_error(self, prop_type, value):
            error = ValidationError(property_name='firewall_rule_icmp',
                                   error_message="Invalid value '%s'." % value)
            self.assertEquals([error],
             self.validator._run_property_type_validators(prop_type,
                                                          'firewall_rule_icmp',
                                                          value))

        prop_type = self.prop_types['firewall_rule_icmp']

        for value in range(0, 254):
            _assert_no_error(self, prop_type, "%d" % value)

        _assert_no_error(self, prop_type, 'echo-request')
        _assert_no_error(self, prop_type, 'echo-reply')

        # ----

        for value in ('255', '2550', '900', '9000', '9999', '-1',
                      'echo', 'request', 'reply', 'bogus',
                      '1echo', '254reply', '%&$', 'echo-request ',
                      '23.2', '001', '010'):
            _assert_error(self, prop_type, value)


if __name__ == '__main__':
    unittest.main()
