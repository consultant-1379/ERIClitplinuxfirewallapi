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

from linuxfirewall_extension.linuxfirewallextension \
    import LinuxFirewallExtension
from litp.extensions.core_extension import CoreExtension
from litp.core.model_manager import ModelManager
from litp.core.model_manager import ModelItem
from litp.core.plugin_manager import PluginManager
from litp.core.plugin_context_api import PluginApiContext
from litp.core.validators import ValidationError
from litp.core import constants


class TestLinuxFirewallPlugin(unittest.TestCase):

    def setUp(self):
        """
        Construct a model, sufficient for test cases
        that you wish to implement in this suite.
        """
        self.model = ModelManager()
        self.plugin_manager = PluginManager(self.model)
        self.context = PluginApiContext(self.model)
        self.plugin_manager.add_property_types(CoreExtension().define_property_types())
        self.plugin_manager.add_item_types(CoreExtension().define_item_types())
        self.plugin_manager.add_default_model()

        self.plugin_manager.add_property_types(LinuxFirewallExtension().define_property_types())
        self.plugin_manager.add_item_types(LinuxFirewallExtension().define_item_types())

    def setup_model(self):
        self.cluster_url = "/deployments/d1/clusters/c1"
        self.n1_url = "/deployments/d1/clusters/c1/nodes/n1"
        created_items = [self.model.create_root_item("root", "/"),
                         self.model.create_item('deployment', '/deployments/d1'),
                         self.model.create_item('cluster', self.cluster_url),
                         self.model.create_item("node", self.n1_url, hostname="n1")]

        [self.assertEquals(ModelItem, type(i)) for i in created_items]
        return created_items

    def _get_data_driven_test_vpath(self, node_type='node'):
        if node_type == 'node':
            return "/deployments/d1/clusters/c1/nodes/n1/configs/fw_conf"
        if node_type == 'ms':
            return "/ms/configs/fw_conf"

    def _get_rule_suffix(self):
        return '/rules/rule'

    def _run_data_driven_test(self, data, command='create'):
        vpath1 = self._get_data_driven_test_vpath('node')
        vpath2 = self._get_data_driven_test_vpath('ms')

        if command == 'create':
            self.setup_model()

            for vpath in (vpath1, vpath2):
                self.model.create_item("firewall-node-config", vpath)

        rule_suffix = self._get_rule_suffix()

        for index, entry in enumerate(data, 1):
            properties = {'name': "00%d rule" % index,
                          'source': "10.247.244.0/22",
                          'destination': "10.140.88.0/21"}

            for option in ['source', 'destination',
                           'chain', 'proto', 'tosource', 'table', 'jump', 'provider']:
                if option in entry.keys():
                    properties[option] = entry[option]

            for vpath in (vpath1, vpath2):
                full_vpath =  vpath + rule_suffix + str(index)
                if command == 'create':
                    errors = self.model.create_item("firewall-rule",
                                                    full_vpath,
                                                    **properties)
                else:
                    errors = self.model.update_item(full_vpath, **properties)

                if 'EXPECTED_ERROR' not in entry.keys() or not entry['EXPECTED_ERROR']:
                    self.assertEqual(0, len(errors))
                else:
                    if not isinstance(errors, list):
                        self.assertFalse(True, "No errors found when following expected: %s" % entry['EXPECTED_ERROR'])

                    if 'prop_name' in entry['EXPECTED_ERROR'].keys():
                        expected_error = ValidationError(property_name=entry['EXPECTED_ERROR']['prop_name'],
                                                         error_message=entry['EXPECTED_ERROR']['msg'],
                                                         error_type=constants.VALIDATION_ERROR)
                    else:
                        expected_error = ValidationError(error_message=entry['EXPECTED_ERROR']['msg'],
                                                         error_type=constants.VALIDATION_ERROR)
                    self.assertTrue(expected_error in errors, errors)

    def test_tosource_scenarios(self):

        data = [{'chain': "POSTROUTING",
                 'proto': "tcp",
                 'tosource': "10.140.88.236",
                 'table': "nat",
                 'jump': "SNAT",
                 'provider': "iptables"},

                {'chain': "POSTROUTING",
                 'proto': "udp",
                 'tosource': "10.140.88.236",
                 'table': "nat",
                 'jump': "SNAT",
                 'provider': "iptables"},


                {'chain': "POSTROUTING",
                 'proto': "tcp",
                 'tosource': "0:0:0:0:0:ffff:a8c:58ec",
                 'table': "nat",
                 'jump': "SNAT",
                 'provider': "iptables",
                 'EXPECTED_ERROR': {'msg': "Invalid value '0:0:0:0:0:ffff:a8c:58ec'. IPv4 Address must be specified",
                                    'prop_name': 'tosource'}},

                {'chain': "POSTROUTING",
                 'proto': "tcp",
                 'tosource': "1..2.2.3",
                 'table': "nat",
                 'jump': "SNAT",
                 'provider': "iptables",
                 'EXPECTED_ERROR': {'msg': "Invalid IPAddress value '1..2.2.3'",
                                    'prop_name': 'tosource'}},


                {'chain': "POSTROUTING",
                 'proto': "tcp",
                 'tosource': "10.140.88.236",
                 'table': "nat",
                 'jump': "SNAT",
                 'provider': "ip6tables",
                 'EXPECTED_ERROR': {'msg': "Invalid property value when also using the tosource property.",
                                    'prop_name': 'provider'}},

                {'chain': "POSTROUTING",
                 'proto': "tcp", 
                 'tosource': "10.140.88.236",
                 'table': "raw",
                 'jump': "SNAT",
                 'provider': "iptables",
                 'EXPECTED_ERROR': {'msg': "Invalid combination of properties, 'table' must be set to nat when 'jump' is set to SNAT.",
                                    'prop_name': 'jump'}},

                {'chain': "POSTROUTING",
                 'proto': "ICMP",
                 'tosource': "10.140.88.236",
                 'table': "nat",
                 'jump': "SNAT",
                 'provider': "iptables",
                 'EXPECTED_ERROR': {'msg': "Invalid value 'ICMP'.",
                                    'prop_name': 'proto'}},

                {'chain': "PREROUTING",
                 'proto': "tcp", 
                 'tosource': "10.140.88.236",
                 'table': "nat",
                 'jump': "SNAT",
                 'provider': "iptables",
                 'EXPECTED_ERROR': {'msg': "Invalid combination of properties, 'chain' must be set to POSTROUTING when 'jump' is set to SNAT.",
                                    'prop_name': 'jump'}},

                {'chain': "POSTROUTING",
                 'proto': "tcp", 
                 'table': "nat",
                 'jump': "SNAT",
                 'provider': "iptables",
                 'EXPECTED_ERROR': {'msg': "Missing 'tosource' property when using 'jump' = SNAT.",
                                    'prop_name': 'jump'}},

                {'chain': "POSTROUTING",
                 'proto': "tcp",
                 'tosource': "10.140.88.236",
                 'table': "nat",
                 'jump': "MASQUERADE",
                 'provider': "iptables",
                 'EXPECTED_ERROR': {'msg': "Invalid 'jump' property when using 'tosource' = 10.140.88.236.",
                                    'prop_name': 'jump'}},

                {'chain': "POSTROUTING",
                 'proto': "tcp",
                 'tosource': "10.140.88.236", 
                 'table': "nat",
                 'jump': "MASQUERADE",
                 'provider': "iptables",
                 'EXPECTED_ERROR': {'msg': "Invalid 'jump' property when using 'tosource' = 10.140.88.236.",
                                    'prop_name': 'jump'}},
        
                {'chain': "PREROUTING",
                 'proto': "tcp", 
                 'table': "nat",
                 'jump': "MASQUERADE",
                 'provider': "iptables",
                 'tosource': "10.20.30.40",
                 'EXPECTED_ERROR': {'msg': "Invalid 'jump' property when using 'tosource' = 10.20.30.40.",
                                    'prop_name': 'jump'}},
        
                {'chain': "POSTROUTING",
                 'proto': "tcp", 
                 'table': "raw",
                 'jump': "MASQUERADE",
                 'provider': "iptables",
                 'tosource': "10.20.30.40",
                 'EXPECTED_ERROR': {'msg': "Invalid 'jump' property when using 'tosource' = 10.20.30.40.",
                                    'prop_name': 'jump'}},

                {'chain': "POSTROUTING",
                 'proto': "tcp", 
                 'tosource': "10.140.88.236",
                 'table': "nat",
                 'jump': "SNAT",
                 'provider': "iptables"},
        
                {'chain': "POSTROUTING",
                 'proto': "tcp", 
                 'table': "nat",
                 'jump': "MASQUERADE",
                 'provider': "iptables"}]

        self._run_data_driven_test(data)

    def test_validate_snat_modify_and_delete_rule(self):

        entry1 = {'chain': "POSTROUTING",
                  'proto': "tcp",
                  'tosource': "10.140.88.236",
                  'table': "nat",
                  'jump': "SNAT",
                  'provider': "iptables"}

        entry2 = {'chain': "POSTROUTING",
                  'proto': "tcp",
                  'tosource': "0:0:0:0:0:ffff:a8c:58ec",
                  'table': "nat",
                  'jump': "SNAT",
                  'provider': "iptables",
                  'EXPECTED_ERROR': {'msg': "Invalid value '0:0:0:0:0:ffff:a8c:58ec'. IPv4 Address must be specified",
                                     'prop_name': 'tosource'}}

        entry3 = {'chain': "POSTROUTING",
                  'proto': "tcp",
                  'tosource': "10.140.88.236",
                  'table': "nat",
                  'jump': "SNAT",
                  'provider': "iptables"}

        data = [entry1, entry2, entry3]
        self._run_data_driven_test(data)

        # ----Modify from ipv4 tcp to udp
        entry1['proto'] = 'udp'
        self._run_data_driven_test([entry1], command='update')

        # ----Modify from ipv4 tcp to invalid protocol
        entry1['proto'] = 'not'
        entry1['EXPECTED_ERROR'] = {'msg': "Invalid value 'not'.",
                                    'prop_name': 'proto'}
        self._run_data_driven_test([entry1], command='update')

        entry2['tosource'] = '10.140.88.236'
        entry2['provider'] = 'ip6tables'

        entry2['EXPECTED_ERROR'] = {'msg': "Invalid property value when also using the tosource property.",
                                     'prop_name': 'provider'}
        self._run_data_driven_test([entry2], command='update')

        # ----Modify from chain=postrouting to invalid chain
        entry3['chain'] = 'X'
        entry3['EXPECTED_ERROR'] = {'msg':"Invalid value 'X'.",
        'prop_name': 'chain'}
        self._run_data_driven_test([entry3], command='update')

        # Delete entry #1
        vpath = self._get_data_driven_test_vpath() + self._get_rule_suffix() + '1'
        errors = self.model.remove_item(vpath)
        self.assertEqual(0, len(errors))
