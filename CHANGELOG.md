## [UNRELEASED] - (2.3.0)

### Changed
- No need to have a ssh config beforehand. If none exists the config for Hyperion is created from scratch.
- Now using "SO_REUSEADDR" option for the server socket. After quitting the server the server port is immediately 
reusable.
- Restructured monitoring with base class and stat monitoring and comp/host monitoring as extra thread extensions.
- Moved the positional `--config` to each subparser so specifying the config before the operation mode is not required 
anymore.
- 'Stop all' command now includes no auto components.
- After 'stop all' a check for all components is triggered on the master server with broadcast option to inform all 
connected clients.
- Introduced default log level in config (set to INFO). This value is only overridden by the '--verbose' start parameter.
- `--no-socket` argument is no longer needed for ui mode. If a config us supplied, the ui will be started in standalone 
mode.
- Introduced option to set the default log umask, meaning the directory permissions for the log and config dirs created
in tmp. To set this option manually add an octal entry (e.g. `0o000` for 775) by key `log_umask` to the system config.
- On stopping a component the monitoring job responsible for the component is not removed anymore, but converted to send
itself a check event, once the component has finished running. This solves the problem of needing to start a check at
the right moment, in order to notify users of a successful component stop.
- Switched to numpy style docstring (https://numpydoc.readthedocs.io/en/latest/format.html).
- Now using black for formatting.
- Added type hints where possible.
- Set host stat precision to 2 digits after the decimal point.

> [!IMPORTANT]
> #### Breaking Changes
> - Dropped support for Python 2
    
### Fixed
- Error on shutdown before config was finished where no master node for dependency was found now is handled.
- On shutdown before the server thread was started, joining the thread made the program crash.
- If no tmux session existed in some OS/tmux configurations, a tmux error was thrown while searching for a maybe already 
active session. This should not happen anymore. (Did not happen on Xenial but on Arch with both running tmux 2.1)
- Switched to full package path imports, since python3 seems not be able to handle those otherwise.
- For compatibility with python3.4, pickle now uses protocol 4.
- Fixed python3 crash on entry point warning log output
- Fixed command to start slaves, since the config argument moved behind the mode argument. 
- Fixed catching unknown host exception inside component check.
- Exit status in visual validation now matches status non-visual validation.
- Fixed multiple exception catches with more than one exceptions in a single catch statement.
- Introduced check if at least one group is defined. If not, the application is shut down with an config parsing error.
- Now handling psutil error that occurs when inside a component check a already dead process' name is looked up.
- Replaced tee logging with tmux pipe-pane. We don't encounter the linebuffering issues described in #38 when 'cat'-ing the piped pane contents directly to the logfile.
- Fetching window(-pane) PIDs is much faster now.
- Checking if a window is busy is much faster now.
- Checking a component now first checks if a component is already being monitored. If it is, true is returned, because this means that a previous check was successful and the process is still running. With this approach only a single constly psutil call to get the process to be monitored is needed, which saves a lot of time in repeated checks.

### Added
- More informative logging output when a file included in the configuration could not be found.
- Single line definition of requirements instead of lists get detected and an appropriate hint is shown in the log.
- Local and remote host stats monitoring. Parameters in the configuration can now also be used to enable or disable stat
monitoring and tune the rates at which monitoring is executed. 
- Detection of multiple definitions of a single group. Multiple group definitions broke the whole startup process.
- After the urwid ui is closed, the stream logging handler printing the log output to the terminal is reattached. In case a full shutdown was requested, instead of waiting without output, the log shows what's going on.
- Added custom log formatters for additional information on higher levels and for colored output in the terminal.

## [2.2.0] - 19.06.2019

### Added
- Enabled configuration of rate at which the monitoring thread checks on components/hosts.
- Added possibility to specify optional requirements for components. This is useful for combination with the exclude
feature.

### Changed
- Moved user interfaces and graph drawing to external libraries

### Fixed
- Having requires or depends defined as empty list does not cause an exception anymore.
- Program will exit with correct exit code on missing urwid installation after showing the error output.

## [2.1.0] - 23.02.2019

### Added
- Mark noauto generated by visual validation mode graph with doubleoctagon.

### Changed
- Moved graph generation to extra python file.
- Before slave sessions and the main session are terminated on full shutdown, each component is stopped.
- Tmux windows for components now start with the shell configured by `shell_path` (defaults to `bin/bash`).

### Fixed
- Logs opened in cli interface that are accessed over ssh won't cause a crash of the UI on connection loss anymore.
- Correct behaivor on component stop: C-c is sent to a window even if a custom stop command is not given.
- Ignore circular dependency error on cleanup. This is triggered by getting the start oder of components for clean
shutdown. When this exception occurs we can assume that no component is running, because a server will not start with 
an invalid config nor reload a config that becomes invalid, meaning the cleanup function is called directly after a 
failed server start so it is okay to ignore the exception in this case.

## [2.0.0-alpha] - 31.01.2019 

### Added
- `verbose_checks` top level field in config. If set to true enables logging stdout and stderr of check commands.
- If sourcing the custom environment file exited with an error while preprocessing, the user is informed via critical 
log output.
- Interactive CLI now supports showing server and slave logs on click of the hostname if it is connected.
- Tagging components with a list of tags is possible by using the `tags` key in the component configuration.
- Specifying a list of exclude tags is possible by using the `exclude` tag in the top level of the configuration. Each
component tagged with a tag included in the exclude list will be removed from the loaded config. This is useful for
dynamic configs (sim and robot specific components in one configured system, for instance) to switch between usage of 
specific components.

### Changed
- Parsing the environment file is more robust now (with exception handling).
- Add enum ExitState in config to define different exit states.
- Starting remote tmux client sessions is not done over ssh anymore but communicated from a client to the server where,
if necessary its forwarded to the server the component is running on, where the bash script for creating a local clone
 session is executed.
- host_states and host_list usage is now consistent across client interfaces and manager instances.
- Dependency model changed to requires/provides to enhance reusability of components. Use the keys `provides` and 
`requires` in component configurations to model dependencies.

### Fixed
- Bug in search component cmd, that would use a dictionary as command to run, when the requested cmd type could not be
found in the list of available commands.
- Restrict usage of standalone mode to having to provide a configuration.
- Safe shutdown is invoked when a slave raises a HostUnknownException while trying to connect to its master server.

## [1.0.0-alpha] - 06.01.2019

### Added
- This changelog
- Graph generated by visual validator mode now clusters by hostname
- Reusing still alive slave sockets after a disconnect on a reconnect attempt (see #30).
- Host status dictionary to keep track of each hosts status (DISCONNECTED, SSH_ONLY and CONNECTED)
- All socket connections are routed over SSH port forwarding (using the control master so every host connection uses
only one port again). Implicitly adds user authentication for UI clients and remote slaves and encrypts the 
communication thus resolving #32 and #28.
  - `forward_over_ssh()` forwards a random local port to the remote server port using the custom ssh config. On success
  the random port is returned to be used .
  - To identify slaves each slave sends an `auth` message containing its hostname on connect because the management
  server gets local sockets without information which remote host the come from. The port of the connection is then 
  mapped to the host from the message payload.
- Possibility to use environment variables for host names in components (e.g `host: ${base-pc}` where base-pc can 
evaluate to anything)
- Broadcasting results of check events is now optional (true by default)
- Adding a `noauto` key to a component config will prevent it from being started automatically by a `start_all` 
procedure. This will also prevent it from being started as dependency of another component which can lead to severe 
start procedure problems thus is it discouraged to depend on noauto components (Resolves #36).
- Usage of optional `stop` commands for components (resolves #34). Note: the component window receives an interrupt, after which the
given stop command is executed.
- Reload config at runtime feature (Resolves #37)
- Option to specify standard shell executable for subprocess calls when the environment file is sourced (config 
preprocessing and when running a component check). The default path '/bin/bash' can be overridden by specifying the 
executable path as value of the `shell_path` field in the system config file.
- Force mode: tries starting a component even if dependencies failed (Resolves #33). In interactive cli press `F` to 
toggle force mode.
- Unit test for slave to server to client connection (by passing on a check event).

### Changed
- Slave session start moved from ssh window of the master server tmux session to remote host tmux session called 
CONFIG_NAME-slave (standard session components get started in too). This way the terminal instance running the slave
can be accessed on the remote host, which is more practical.
- Moved `setup_ssh_config()` method to a static context so that it can be run without having a reference to a manager
AbstractManager instance.
- Socket servers are now always bound to loopback to make connections inaccessible from other network devices forcing 
clients to use ssh forwarding.
- Moved localhost checks in RemoteClientInterfaces to the BaseClient class.
- Renamed `set_component_ids` to `conf_preprocessing` and added resolving hosts that are given as env variables. For
the sake of using variables defined in the custom environment file (if any is given) it is sourced via subprocess and 
the env variables are analyzed.
- Only broadcast local check events or if a slave did not answer (in time) to prevent sending a check event twice 
(received check events are forwarded automatically)
- Major changes in generated graph layout:
    - Rankdir is now from R to L, hostnames in node labels appear after a
    linebreak, are slightly smaller and colored green for better overview.
    - Node style changed to squares.
    - Edge style changed from splines to polyline (less ambiguous overlap).
    - Rank is globally managed, not cluster specific.
- Replaced enum dependency with enum34
- On component (depedency) start don't always wait the whole component wait time. Instead, checks are performed 
periodically until successful, if the component wait time is over, each check is counted as try and on 4 unsuccessful 
tries the process is interpreted as failed start.
- Most component check results of checks performed during component startup (including dependencies) are not 
broadcasted to ui clients. Only the last check of the component (thus not a intermediate but a meaningful result) will 
be published (Resolves #35). 
- Special order of component cmds in configurations is not required anymore since the function `get_component_cmd` takes
 care of that now.
- Disabled automatic `check all` action on interactive cli start.
- Disabled PyQt gui for now, since currently it is not compatible with the server/client architecture.

### Fixed
- Stability of execute mode (all commands now work again for remote or local components)
- validator mode: moved setting component ids to a function that is called before analysing the config so that it now
is able to find the id key each component dict.
- visual validator mode
- Trying to send commands to not connected slaves
- Set ssh connect option batchmode to disable being prompted for a password, when auth via ssh keys is not successful, 
because the tmux window would be kept busy and the application would loop endlessly waiting for the ssh process to 
finish.
- On slave disconnect pass host name instead of the ip to the disconnect event (caused additional host entries 
in host_list see #29)
- Add a check if ssh is actually running instead of checking if only the window exists before attempting a slave start.
That would cause an incorrect status of SSH_ONLY when the slave connection failed instead of DISCONNECTED as it should
be.
- SlaveManager check_buffer content validation: changed to None check instead of single if because a value of 0 as
answer (currently RUNNING) would be interpreted as no answer and result in an UNREACHABLE event.
- Lowered CPU usage of `clientInterface` by adding sleep to the messaging loop.
- If custom environment was given as relative path, absolute path is joined and saved (necessary to source before 
running checks in subprocess)
- Use sleep in slave messaging loop to fix CPU leak.
- Reconnect event (sent on ssh reconnect) resulted in wrong host status CONNECTED, now it is set to SSH_ONLY.
- SlaveReconnect being handled by client interfaces the right way.

## 0.0.1 - 12.12.2018
First alpha release