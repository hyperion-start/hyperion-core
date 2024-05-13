from threading import Thread, Lock
import os
import psutil
import logging
import sys
import time
import hyperion.lib.util.config as config
import hyperion.lib.util.events as events
from subprocess import call
from psutil import Process, NoSuchProcess
import socket

from typing import Union, Any, Tuple

import queue
    

class ComponentMonitorJob(object):
    """Abstract class that represents a component monitoring job (local or remote)."""

    def __init__(self, pid: int, comp_id: str) -> None:
        """Initializes component monitoring job.

        Parameters
        ----------
        pid : int
            Process id of the component.
        comp_id : str
            Id of the component (name@host)
        """
        
        self.pid = pid
        self.comp_id = comp_id
        self.error_msg = f"Component '{comp_id}' crashed!"
        self.is_cancelled = False

    def run_check(self) -> Union[bool, events.CrashEvent, events.CheckEvent]:
        """You need to override this function in monitoring subclasses. It is called in the main monitoring thread.

        Returns
        -------
        Union[bool, events.CrashEvent, events.CheckEvent]
            True on a successful check, generated CheckEvent for stopping, otherwise a CrashEvent is generated

        Raises
        ------
        NotImplementedError
            If this function is not overridden in subclass 
        """
        raise NotImplementedError


class CancellationJob(ComponentMonitorJob):
    def run_check(self) -> Union[bool, events.CrashEvent, events.CheckEvent]:
        # Is never called here
        raise NotImplementedError

    def __init__(self, pid: int, comp_id : str) -> None:
        """Creates a cancellation job for a component.

        Parameters
        ----------
        pid : int
            Process id of the component.
        comp_id : str
            Id of the component (name@host)
        """
        super(CancellationJob, self).__init__(pid, comp_id)


class LocalComponentMonitoringJob(ComponentMonitorJob):
    """Class that represents a local component monitoring job."""

    def __init__(self, pid: int, comp_id : str) -> None:
        """Creates a monitoring job for a local component.

        Parameters
        ----------
        pid : int
            Process id of the component.
        comp_id : str
            Id of the component (name@host)
        """
        super(LocalComponentMonitoringJob, self).__init__(pid, comp_id)

    def run_check(self) -> Union[bool, events.CrashEvent, events.CheckEvent]:
        """Runs a check if the pid exists and has not finished yet.

        Returns
        -------
        Union[bool, events.CrashEvent, events.CheckEvent]
            True if the component is running, generated `CheckEvent` for stopped if cancelled, otherwise returns a generated `CrashEvent`.
        """
        try:
            proc = Process(self.pid)
            if proc.is_running():
                return True
        except NoSuchProcess:
            pass
        if self.is_cancelled:
            return events.CheckEvent(self.comp_id, config.CheckState.STOPPED)
        return events.CrashEvent(self.comp_id)

    def info(self) -> str:
        """Generate a status information for the job describing what is being monitored.

        Returns
        -------
        str
            Information about this job.
        """

        return f"Running check for local component '{self.comp_id}' with pid {self.pid}"


class RemoteComponentMonitoringJob(ComponentMonitorJob):
    """Class that represents a remote component monitoring job."""

    def __init__(self, pid: int, comp_id : str, hostname: str, host_status: dict[str, Any]) -> None:
        """Creates a remote component monitoring job.

        Parameters
        ----------
        pid : int
            Process id on the remote machine.
        comp_id : str
            Id of the component (name@host)
        hostname : str
            Host the component is run on.
        host_status : dict[str, Any]
            Dictionary of connected hosts' status'.
        """
        
        super(RemoteComponentMonitoringJob, self).__init__(pid, comp_id)
        self.hostname = hostname
        self.host_status = host_status

    def run_check(self) -> Union[bool, events.CrashEvent]:
        """Runs a check if a remote process is still running.

        Returns
        -------
        Union[bool, events.CrashEvent]
            True if the component is still running or the host is not reachable, otherwise a `CrashEvent` is generated.
        """

        if self.host_status.get(self.hostname):
            cmd = f'ssh -F {config.CUSTOM_SSH_CONFIG_PATH} {self.hostname} "ps -p {self.pid}" 2> /dev/null 1> /dev/null'
            if call(cmd, shell=True) == 0:
                return True
            else:
                return events.CrashEvent(self.comp_id, True)
        # Return true because no information can be retrieved. The connection to the host has to be reestablished first.
        return True

    def info(self) -> str:
        """Generate a status information for the job describing what is being monitored.

        Returns
        -------
        str
            Information about this job.
        """        

        return f"Running check for remote component {self.comp_id} with pid {self.pid} on host {self.hostname}"


class LocalStatMonitorJob(object):

    @staticmethod
    def request_stats() -> events.StatResponseEvent:
        """You need to override this function in monitoring subclasses. It is called in the main monitoring thread.

        Returns
        -------
        events.StatResponseEvent
            Stat response
        """

        load = os.getloadavg()[0]
        cpu = psutil.cpu_percent(0.5)
        mem = psutil.virtual_memory().percent
        return events.StatResponseEvent(load, cpu, mem, socket.gethostname())


class HostMonitorJob(object):
    """Class representing a host monitoring job."""
    def __init__(self, pid: int, hostname: str, host_status: dict[str, int], host_lock: Lock) -> None:
        """Create host monitoring job.

        Parameters
        ----------
        pid : int
            Process id of the ssh connection.
        hostname : str
            Name of the host connected to.
        host_status : dict[str, int]
            Status of the used hosts.
        host_lock : Lock
            Lock that has to be acquired in order to write to the host status dictionary.
        """

        self.pid = pid
        self.hostname = hostname
        self.host_status = host_status
        self.host_lock = host_lock
        self.error_msg = f"Lost connection to '{hostname}'!"

    def run_check(self) -> Union[events.DisconnectEvent, bool]:
        try:
            proc = Process(self.pid)
            if proc.is_running():
                return True
        except NoSuchProcess:
            pass

        self.host_lock.acquire()
        self.host_status.pop(self.hostname, None)
        self.host_lock.release()

        return events.DisconnectEvent(self.hostname)

    def info(self) -> str:
        return f"Running ssh host check for {self.hostname} with pid {self.pid}"


class BaseMonitorThread(Thread):
    """Baseclass for monitoring solutions."""

    def __init__(self) -> None:
        super(BaseMonitorThread, self).__init__()
        self.logger = logger = logging.getLogger(__name__)
        logger.setLevel(config.DEFAULT_LOG_LEVEL)
        self.subscribed_queues: list[queue.Queue] = []
        self.end = False
        logger.debug("Initialized thread")

    def kill(self) -> None:
        """Shuts down the thread by signalling the run function to end.
        """

        logger = logging.getLogger(__name__)
        logger.debug("Killing process monitoring thread")
        self.end = True

    def add_subscriber(self, queue: queue.Queue) -> None:
        """Adds a subscriber to the list of queues to send notifications to.

        Parameters
        ----------
        queue : queue.Queue
            Subscribing queue that will get notifications by this thread.
        """

        logger = logging.getLogger(__name__)
        logger.debug("Adding subscriber")
        self.subscribed_queues.append(queue)

    def remove_subscriber(self, queue: queue.Queue) -> None:
        """Remove a subscriber from the list of queues to send notifications to.

        Parameters
        ----------
        queue : queue.Queue
            Unsubscribing queue that will get no notifications by this thread anymore.
        """
        
        logger = logging.getLogger(__name__)
        logger.debug("Removing subscriber")
        self.subscribed_queues.remove(queue)

    def run(self) -> None:
        """Method that needs to be implemented by extending classes."""
        raise NotImplementedError


class StatMonitor(BaseMonitorThread):
    """This class is an extra thread class to handle stat monitoring"""
    def __init__(self) -> None:
        """Initialize thread"""
        super(StatMonitor, self).__init__()

    def run(self) -> None:
        """Starts the monitoring thread.
        """

        self.logger.debug("Started run function")
        while not self.end:
            for subscriber in self.subscribed_queues:
                subscriber.put(LocalStatMonitorJob.request_stats())
            time.sleep(1/config.LOCAL_STAT_MONITOR_RATE)


class ComponentMonitor(BaseMonitorThread):
    """This class is for monitoring components and host connections."""
    def __init__(self, queue: queue.Queue) -> None:
        """Initializes the monitoring thread with its input queue.

        Parameters
        ----------
        queue : queue.Queue
            Input queue the monitor retrieves its jobs from
        """

        super(ComponentMonitor, self).__init__()
        self.job_queue = queue

    def run(self) -> None:
        """Starts the monitoring thread.
        """

        self.logger.debug("Started run function")
        while not self.end:

            comp_jobs = []
            cancellations = []
            jobs: list[Union[HostMonitorJob, ComponentMonitorJob]] = []
            already_handleled = {}
            already_removed = {}
            # Get all enqueued jobs for this iteration
            while not self.job_queue.empty():
                mon_job = self.job_queue.get()
                if isinstance(mon_job, HostMonitorJob):
                    jobs.append(mon_job)
                if isinstance(mon_job, ComponentMonitorJob) and mon_job.comp_id not in already_handleled:
                    comp_jobs.append(mon_job)
                    already_handleled[mon_job.comp_id] = True
                if isinstance(mon_job, CancellationJob) and mon_job.comp_id not in already_removed:
                    cancellations.append(mon_job)
                    already_removed[mon_job.comp_id] = True

            # Remove all jobs that received a cancellation from the job list
            # remove = []
            for mon_job in cancellations:
                for comp_job in comp_jobs:
                    if mon_job.comp_id is comp_job.comp_id:
                        comp_job.is_cancelled = True
                        # Previous way of cancelling jobs. Lets keep this for now
                       # remove.append(comp_job)
           # [comp_jobs.remove(job) for job in remove]

            # Reorder job list to first check the hosts, then check the components because this makes sense
            jobs.extend(comp_jobs)
            for mon_job in jobs:
                ret = mon_job.run_check()
                if ret is True:
                    # If job is ok, put it back for the next iteration
                    self.job_queue.put(mon_job)
                else:
                    # If job is not ok, notify subscribers
                    if not mon_job.is_cancelled:
                        self.logger.error(mon_job.error_msg)
                    self.logger.debug("Notifying mon subscribers about failed check")
                    for subscriber in self.subscribed_queues:
                        subscriber.put(ret)

            time.sleep(1/config.MONITORING_RATE)
