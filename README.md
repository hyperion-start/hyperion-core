# Hyperion

## What is Hyperion

Hyperion is an engine designed to launch and monitor user defined components using YAML configuration files.  
Inspired by [vdemo](https://code.cor-lab.org/projects/vdemo) and [TMuLE](https://github.com/marc-hanheide/TMuLE) (see [vdemo and TMuLE assessment](https://github.com/DavidPL1/Hyperion/wiki/vdemo-and-TMuLE-assessment))

## How does it work
Hyperion (like TMuLE) is written in Python and utilizes the [tmux library for python](https://github.com/tmux-python/libtmux) to start components in detached sessions. For each host defined in the components a master session is created, in which each component will be started in a window.

## Usage

Hyperion is planned to support various modes, but currently the main developing focus is set on the 'run' and the 'slave' mode:

### Run mode

```
hyperion --config systems/demo.yaml run
```

The run mode will initialize the configured system with the executing host as controlling instance. The the used components will be copied to the hosts they will be run on and a GUI to start, monitor and stop components will show.

### Slave mode

```
hyperion --config components/top.yaml slave
```

The slave mode will search for an already running tmux slave session on the executing host and start one, if it's not found. Then only the specified component will be started a new window within the slave session. 

```
hyperion --config components/top.yaml slave --kill
```

When the optional kill argument is provided, the window belonging to the specified component is searched in the slave session and if found, a SIGINT signal is sent to the running program and after that the window is killed.

---------

For more information about the developement and upcoming features visit the [wiki](https://github.com/DavidPL1/Hyperion/wiki)
