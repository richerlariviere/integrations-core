# (C) Datadog, Inc. 2020-present
# All rights reserved
# Licensed under Simplified BSD License (see LICENSE)
import os

from collections import OrderedDict
import click
import json
import pyperclip
import yaml

from ...console import CONTEXT_SETTINGS


class OidNodeInvalid(Exception):
    """Missing OID, name or class in oid node"""
    pass


class OidNode:
    def __init__(self, mib, mib_json_node):
        """
        Creates an oid node from a mib and a mib json node

        Example of mib json node:
        ```json
        {
            "name": "mIBMinorVersionNumber",
            "oid": "1.3.6.1.4.1.674.10892.1.1.2",
            "nodetype": "scalar",
            "class": "objecttype",
            "syntax": {
              "type": "DellUnsigned8BitRange",
              "class": "type"
            },
            "maxaccess": "read-only",
            "status": "mandatory",
            "description": "0001.0002 This attribute defines the minor version number of the Dell Enterprise Server Group MIB (Management Information Base)."
        }
        ```
        """
        if 'oid' not in mib_json_node or 'name' not in mib_json_node or 'class' not in mib_json_node:
            raise OidNodeInvalid

        mib_class = mib_json_node['class']

        # The OBJECT-TYPE is defined by SNMP v1 and is used as a container for
        # storing information about the managed device, or some measured value on the device.
        # More details:
        # https://www.ibm.com/support/knowledgecenter/en/SSSHTQ_8.1.0/com.ibm.netcool_OMNIbus.doc_8.1.0/omnibus/wip/ua_mibmgr/reference/omn_ref_mib_mibobjects.html
        if mib_class != 'objecttype':
            self.is_object = False
            return

        self.is_object = True

        self.name = mib_json_node['name']
        self.oid = mib_json_node['oid']
        self.mib = mib
        self.node = mib_json_node
        self.node['mib'] = mib
        self.is_readable = True
        self.is_middle_node = False
        self.is_unknown = False
        self.max_access = None
        self.description = None

        if 'maxaccess' in mib_json_node:
            self.max_access = mib_json_node['maxaccess']

        if 'nodetype' in mib_json_node:
            self.node_type = mib_json_node['nodetype']
            if self.node_type != 'table' and self.node_type != 'scalar' and self.node_type != 'column':
                self.is_middle_node = True
        else:
            self.is_unknown = True

        if 'description' in mib_json_node:
            self.description = mib_json_node['description']


def _list_mib_filenames(mibs_directory, mib_file_extension='.my'):
    return [os.path.splitext(os.path.basename(a))[0] for a in os.listdir(mibs_directory) if a.endswith(mib_file_extension)]


def _compile_mib_to_json(mib, destination_directory):
    from pysmi.codegen import JsonCodeGen
    from pysmi.compiler import MibCompiler
    from pysmi.writer import FileWriter
    from pysmi.reader import FileReader, HttpReader
    from pysmi.searcher import AnyFileSearcher, StubSearcher
    from pysmi.parser import SmiV1CompatParser

    mib_stubs = JsonCodeGen.baseMibs

    reader = HttpReader('raw.githubusercontent.com', 80, '/projx/snmp-mibs/master/@mib@')

    compile_documentation = True

    # Compiler infrastructure
    searchers = [AnyFileSearcher(destination_directory).setOptions(exts=['.json']), StubSearcher(*mib_stubs)]

    code_generator = JsonCodeGen()

    file_writer = FileWriter(destination_directory).setOptions(suffix='.json')

    mib_compiler = MibCompiler(
        SmiV1CompatParser(tempdir=''),
        code_generator,
        file_writer
    )

    mib_compiler.addSources(reader)
    mib_compiler.addSources(FileReader(destination_directory))

    mib_compiler.addSearchers(*searchers)

    processed = mib_compiler.compile(
        mib, **dict(noDeps=False,
                    rebuild=False,
                    dryRun=False,
                    dstTemplate=None,
                    genTexts=compile_documentation,
                    textFilter=False and (lambda symbol, text: text) or None,
                    writeMibs=True,
                    ignoreErrors=False)
    )

    return processed


def _load_json_module(source_directory, mib):
    try:
        with open(os.path.join(source_directory, mib + '.json')) as mib_json:
            return json.load(mib_json)
    except FileNotFoundError:
        return None


def _load_module_or_compile(source_directory, mib):
    mib_json = _load_json_module(source_directory, mib)
    if mib_json is not None:
        return mib_json

    # compile and load
    processed = _compile_mib_to_json(mib, source_directory)
    print('*** {} module {}'.format(mib, processed[mib]))
    if processed[mib] != 'missing':
        mib_json = _load_json_module(source_directory, mib)
        return mib_json

    return None


def _filter_mib_oids(mib, json_mib, filter_data):
    # skip filtering if no filter is provided for this mib
    if filter_data is None or mib not in filter_data:
        return json_mib

    filtered_json_oids = {}
    for filter_oid_name in filter_data[mib]:
        # recursively add oids under filter_oid_name
        if filter_oid_name not in json_mib:
            continue

        # add only oids under filter_oid
        root_node = json_mib[filter_oid_name]
        filtered_oids = {node_name: node for (node_name, node) in json_mib.items() if
                         'oid' in node and root_node['oid'] in node['oid']}
        filtered_json_oids.update(filtered_oids)

    return filtered_json_oids


def _extract_oids_from_mibs(mibs_directory, filter_path=None):
    source_directory = mibs_directory

    filter_data = None
    if filter_path is not None and os.path.isfile(filter_path):
        with open(filter_path) as f:
            filter_data = yaml.safe_load(f)

    mib_to_load_list = _list_mib_filenames(mibs_directory)
    mib_to_load_list.sort()
    json_mibs = {}
    for mib in mib_to_load_list:
        json_mib = _load_module_or_compile(source_directory, mib)
        if json_mib is None:
            continue

        # apply filter
        filtered_json_mib = _filter_mib_oids(mib, json_mib, filter_data)
        json_mibs[mib] = filtered_json_mib

    oid_list = []
    for mib, json_mib in json_mibs.items():
        for key in json_mib:
            try:
                oid_node = OidNode(mib, json_mib[key])
            except OidNodeInvalid:
                continue

            if not oid_node.is_object:
                continue

            if not oid_node.is_readable:
                continue

            if oid_node.is_middle_node:
                continue

            if oid_node.is_unknown:
                print('==> Unknown node type: {}:{} [{}]'.format(oid_node.mib, oid_node.name, oid_node.oid))

            oid_list.append(oid_node)

    return oid_list


def _get_profiles_site_root():
    # type: () -> str
    return '/Users/paola.ducolin/dd/integrations-core/snmp/datadog_checks/snmp/data/profiles'


def _resolve_profile_file(profile_file):
    # type: (str) -> str
    if os.path.isabs(profile_file):
        return profile_file

    return os.path.join(_get_profiles_site_root(), profile_file)


def _read_profile_definition(profile_filename):
    # type: (str) -> Dict[str, Any]
    with open(_resolve_profile_file(profile_filename)) as f:
        return yaml.safe_load(f)


def _recursively_expand_profile(filename, data):
    # type: (str, Dict[str, Any]) -> None
    """
    Update `data` in-place with the contents of base profile files listed in the 'extends' section.

    Base profiles should be referenced by filename, which can be relative (built-in profile)
    or absolute (custom profile).

    Raises:
    * Exception: if any definition file referred in the 'extends' section was not found or is malformed.
    """

    expanded_data = _read_profile_definition(filename)
    expanded_metrics = expanded_data.get('metrics', [])
    existing_metrics = data.get('metrics', [])

    data['metrics'] = expanded_metrics + existing_metrics  # NOTE: expanded metrics must be added first.

    extends = expanded_data.get('extends', [])

    for base_filename in extends:
        _recursively_expand_profile(base_filename, data)


def _extract_oid_collection_from_profile_data(data):
    # type: (Dict[str, Any]) -> Dict[str, Any]
    """
    Extract oids from profile `data`

    Return a collection of oid nodes, indexed by their oid
    """
    oid_collection = {}
    for metric in data['metrics']:
        oid_node = {'mib': metric['MIB']}
        if 'table' in metric:
            table = metric['table']
            if 'OID' in table:
                oid_node['name'] = table['name']
                oid_node['oid'] = table['OID']
                oid_collection[table['OID']] = oid_node
            if 'symbols' in table:
                for symbol in table['symbols']:
                    if 'OID' in symbol:
                        oid_node['name'] = symbol['name']
                        oid_node['oid'] = symbol['OID']
                        oid_collection[symbol['OID']] = oid_node
        elif 'symbol' in metric:
            symbol = metric['symbol']
            if 'OID' in symbol:
                oid_node['name'] = symbol['name']
                oid = symbol['OID']
                # remove trailing 0 from oid
                if oid.endswith('.0'):
                    oid = oid[:-2]
                oid_node['oid'] = oid
                oid_collection[oid] = oid_node
    return oid_collection


@click.command(context_settings=CONTEXT_SETTINGS, short_help='Generate SNMP profile from a collection of MIB files')
@click.argument('mibs_directory')
@click.option('--oid_filter_path', help='Path to filter')
@click.pass_context
def generate_profile_from_mibs(ctx, mibs_directory, oid_filter_path=None):
    # type: (str, str) -> [Any]
    """
    Generate an SNMP profile from MIBs. Accepts a directory path containing mib files
    to be used as source to generate the profile, along with a filter if a device or
    family of devices support only a subset of oids from a mib.
    The oid filter is expected as an yaml file containing a collection of mibs and the
    filtered oid nodes.
    For example:
    ```yaml
    RFC1213-MIB:
    - system
    - interfaces
    - ip
    ```

    Return a list of SNMP metrics and copy its yaml dump on the clipboard
    Metric tags need to be added manually
    """
    profile_oid_collection = OrderedDict()
    # build profile
    for oid_node in _extract_oids_from_mibs(mibs_directory, oid_filter_path):
        mib = oid_node.mib
        name = oid_node.name
        oid = oid_node.oid

        if oid_node.node_type == 'table':
            profile_node = {'MIB': mib}
            table = {'name': name, 'OID': oid}
            if oid_node.description is not None:
                table['description'] = oid_node.description
            symbols = []
            # find table
            if oid in profile_oid_collection:
                symbols = profile_oid_collection[oid]['symbols']

            profile_node['table'] = table
            profile_node['symbols'] = symbols
            profile_oid_collection[oid] = profile_node
        elif oid_node.node_type == 'column':
            # Table oids are defined as:
            # <TABLE_OID>.<TABLE_ENTRY>.<COLUMN_NUM>
            # where <TABLE_ENTRY> is always 1
            table_oid = '.'.join(oid.split('.')[:-2])
            if table_oid not in profile_oid_collection:
                # create table if it does not exist yet
                table = {'OID': table_oid}
                symbols = []
                profile_node['table'] = table
                profile_node['symbols'] = symbols
                profile_oid_collection[table_oid] = profile_node

            symbol = {'name': name, 'OID': oid}
            if oid_node.description is not None:
                symbol['description'] = oid_node.description
            symbols = profile_oid_collection[table_oid]['symbols']
            symbols.append(symbol)
            profile_oid_collection[table_oid]['symbols'] = symbols
        elif oid_node.node_type == 'scalar':
            profile_node = {'MIB': mib}
            if not oid.endswith('.0'):
                oid = oid + '.0'
            symbol = {'name': name, 'OID': oid}
            if oid_node.description is not None:
                symbol['description'] = oid_node.description
            profile_node['symbol'] = symbol
            profile_oid_collection[oid] = profile_node

    metrics = []
    for key, item in profile_oid_collection.items():
        metrics.append(item)

    pyperclip.copy(yaml.dump({'metrics': metrics}))
    print('Profile yaml dump copied to your clipboard')

    return metrics


@click.command(context_settings=CONTEXT_SETTINGS, short_help='Update SNMP profile from a new SNMP profile')
@click.argument('profile_old')
@click.argument('profile_new')
@click.pass_context
def update_profile(ctx, profile_old, profile_new):
    # type: (str, [Any]) -> [Any]
    """
    Update an old SNMP profile from a new list of metrics, adding metrics
    that are not defined in the old profile.
    Returns a list of metrics, and prints its yaml dump

    You'll need to install pysnmp manually beforehand.
    """

    # load data from old profile
    data = OrderedDict()
    _recursively_expand_profile(profile_old, data)
    profile_old_oid_collection = _extract_oid_collection_from_profile_data(data)

    # load metrics from new profile
    metrics = _read_profile_definition(profile_new)['metrics']

    output = []
    for oid_node in metrics:
        if 'table' in oid_node:
            oid = oid_node['table']['OID']
        elif 'symbol' in oid_node:
            oid = oid_node['symbol']['OID']
        else:
            continue

        if oid not in profile_old_oid_collection.keys():
            output.append(oid_node)
        else:
            pass

    print('Additional oid metrics: {}'.format(len(output)))
    pyperclip.copy(yaml.dump({'metrics': output}))
    print('Additional metrics yaml dump copied to your clipboard')
