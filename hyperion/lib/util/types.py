from typing import TypedDict

Component = TypedDict('Component', {
    'cmd': list[dict[str, str]],
    'depends': list[str],
    'host': str,
    'id': str,
    'name': str,
    'provides': list[str],
    'requires': list[str],
    'optional-requires': list[str],
    'wait': float,
    'tags': list[str]
}, total=False)

Group = TypedDict('Group', {'components': list[Component], 'name': str})

Config = TypedDict('Config', {
    'env': str,
    'name': str,
    'groups': list[Group],
    'slave_hyperion_source_path': str,
    'shell_path': str,
    'exclude': list[str],
    'monitoring_rate': int,
    'verbose_checks': bool,
    'local_monitor': bool,
    'local_stat_rate': float,
    'remote_monitor': bool,
    'remote_stat_rate': float,
    'log_umask': str,
}, total=False)
