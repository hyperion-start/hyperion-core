from threading import Thread, Lock
import logging
import sys
import time
import hyperion.lib.util.config as config
from os import system
from subprocess import call
from psutil import Process, NoSuchProcess
is_py2 = sys.version[0] == '2'
if is_py2:
    import Queue as Queue
else:
    import queue as Queue
    

class ComponentMonitorJob(object):
    """Abstract class that represents a component monitoring job (local or remote)."""

    def __init__(self, pid, comp_name):
        """Initializes component monitoring job.

        :param pid: Process id of the component
        :type pid: int
        :param comp_name: Name of the component
        :type comp_name: str
        """
        self.pid = pid
        self.comp_name = comp_name

    def run_check(self):
        """You need to override this function in monitoring subclasses. It is called in the main monitoring thread.

        :return: True on a successful check, otherwise a CrashEvent is generated
        :rtype: bool or CrashEvent
        """


class LocalComponentMonitoringJob(ComponentMonitorJob):
    """Class that represents a local component monitoring job."""

    def __init__(self, pid, comp_name):
        """Creates a monitoring job for a local component.

        :param pid: Process id of the component
        :type pid: int
        :param comp_name: Name of the component
        :type comp_name: str
        """

        super(LocalComponentMonitoringJob, self).__init__(pid, comp_name)

    def run_check(self):
        """Runs a check if the pid exists and has not finished yet.

        :return: True if the component is running, otherwise returns a generated ``LocalCrashEvent``
        :rtype bool or LocalCrashEvent
        """
        try:
            proc = Process(self.pid)
            if proc.is_running():
                return True
        except NoSuchProcess:
            pass
        return CrashEvent(self.comp_name)

    def info(self):
        """Generate a status information for the job describing what is being monitored.

        :return: Information about this job
        :rtype: str
        """

        return "Running check for local component %s with pid %s" % (self.comp_name, self.pid)


class RemoteComponentMonitoringJob(ComponentMonitorJob):
    """Class that represents a remote component monitoring job."""

    def __init__(self, pid, comp_name, hostname, host_status):
        """Creates a remote component monitoring job.

        :param pid: Process id on the remote machine
        :type pid: int
        :param comp_name: Name of the monitored component
        :type comp_name: str
        :param hostname: Name of the host running the component
        :type hostname: str
        """

        super(RemoteComponentMonitoringJob, self).__init__(pid, comp_name)
        self.hostname = hostname
        self.host_status = host_status

    def run_check(self):
        """Runs a check if a remote process is still running.

        :return: True if the component is still running or the host is not reachable, otherwise a ``RemoteCrashEvent`` is generated.
        :rtype: bool or RemoteCrashEvent
        """

        if self.host_status.get(self.hostname):
            cmd = 'ssh -F %s %s "ps -p %s > /dev/null"' % (config.CUSTOM_SSH_CONFIG_PATH, self.hostname, self.pid)
            if call(cmd, shell=True) == 0:
                return True
            else:
                return RemoteCrashEvent(self.comp_name, self.hostname)
        # Return true because no information can be retrieved. The connection to the host has to be reestablished first.
        return True

    def info(self):
        """Generate a status information for the job describing what is being monitored.

        :return: Information about this job
        :rtype: str
        """

        return "Running check for remote component %s with pid %s on host %s" % (self.comp_name, self.pid,
                                                                                 self.hostname)


class HostMonitorJob(object):
    """Class representing a host monitoring job."""
    def __init__(self, pid, hostname, host_status, host_lock):
        """Create host monitoring job.

        :param pid: Process id of the ssh connection
        :type pid: int
        :param hostname: Name of the host connected to
        :type hostname: str
        :param host_status: Status of the used hosts
        :type host_status: dict
        :param host_lock: Lock that has to be acquired in order to write to the host status dictionary.
        :type host_lock: Lock
        """
        self.pid = pid
        self.hostname = hostname
        self.host_status = host_status
        self.host_lock = host_lock

    def run_check(self):
        try:
            proc = Process(self.pid)
            if proc.is_running() and system("exec >(ping %s -c 10 >/dev/null) </dev/null" % self.hostname) is 0:
                return True
        except NoSuchProcess:
            pass

        self.host_lock.acquire()
        self.host_status[self.hostname] = None
        self.host_lock.release()

        return DisconnectEvent(self.hostname)

    def info(self):
        return "Running ssh host check for %s with pid %s" % (self.hostname, self.pid)


class CrashEvent(object):
    """Superclass to model a component crash.

    Provides the name of the crashed component."""

    def __init__(self, comp_name):
        """Initializes the crash event assigning the component name

        :param comp_name: Name of the crashed component
        :type comp_name: str
        """

        self.comp_name = comp_name


class LocalCrashEvent(CrashEvent):
    """Crash event subclass for local component crashes.

    Provides the name of the crashed component and a short message.
    """

    def __init__(self, comp_name):
        """Creates a local crash event class with a component name and generates a short message.

        :param comp_name: Name of the crashed component
        :type comp_name: str
        """

        super(LocalCrashEvent, self).__init__(comp_name)
        self.message = 'Component %s crashed on localhost' % comp_name


class RemoteCrashEvent(CrashEvent):
    """Crash event subclass for remote component crashes.

    Provides the name of the crashed component along with the host it ran on and a short message.
    """

    def __init__(self, comp_name, hostname):
        """Creates a remote crash event with a component name and a host generating a short message.

        :param comp_name: Name of the crashed component
        :type comp_name: str
        :param hostname: Name of the host the component was running on
        :type hostname: str
        """

        super(RemoteCrashEvent, self).__init__(comp_name)
        self.hostname = hostname
        self.message = 'Component %s crashed on remote host %s' % (comp_name, hostname)


class DisconnectEvent(object):
    """Class representing a disconnect event for remote hosts."""

    def __init__(self, hostname):
        """Creates a disconnect event with a hostname and generates a short message."""
        self.hostname = hostname
        self.message = 'Lost connection to remote host %s' % hostname


class MonitoringThread(Thread):
    """This class is monitoring thread that extends the threading.Thread class."""

    def __init__(self, queue):
        """Initializes the monitoring thread with its input queue.

        :param queue: Input queue the monitor retrieves its jobs from
        :type queue: Queue.Queue
        """

        logger = logging.getLogger(__name__)
        logger.setLevel(logging.DEBUG)
        logger.debug("Initialized thread")
        super(MonitoringThread, self).__init__()
        self.job_queue = queue
        self.subscribed_queues = []
        self.end = False

    def kill(self):
        """Shuts down the thread by signalling the run function to end.

        :return: None
        """

        logger = logging.getLogger(__name__)
        logger.debug("Killing process monitoring thread")
        self.end = True

    def add_subscriber(self, queue):
        """Adds a subscriber to the list of queues to send notifications to.

        :param queue: Subscribing queue that will get notifications by this thread
        :type queue: Queue.Queue
        :return: None
        """

        logger = logging.getLogger(__name__)
        logger.debug("Added subscriber")
        self.subscribed_queues.append(queue)

    def run(self):
        """Starts the monitoring thread.

        :return: None
        """

        logger = logging.getLogger(__name__)
        logger.setLevel(logging.DEBUG)
        logger.debug("Started run funtion")
        while not self.end:

            comp_jobs = []
            jobs = []
            already_handleled = {}
            # Get all enqueued jobs for this iteration
            while not self.job_queue.empty():
                mon_job = self.job_queue.get()
                if isinstance(mon_job, HostMonitorJob):
                    jobs.append(mon_job)
                if isinstance(mon_job, ComponentMonitorJob) and mon_job.comp_name not in already_handleled:
                    comp_jobs.append(mon_job)
                    already_handleled[mon_job.comp_name] = True

            # Reorder job list to first check the hosts, then check the components because this makes sense
            jobs.extend(comp_jobs)
            for mon_job in jobs:
                logger.debug(mon_job.info())
                ret = mon_job.run_check()
                if ret is True:
                    logger.debug("S'all good man")
                    # If job is ok, put it back for the next iteration
                    self.job_queue.put(mon_job)
                else:
                    # If job is not ok, notify subscribers
                    logger.debug("Check failed, notifying subscribers")
                    for subscriber in self.subscribed_queues:
                        subscriber.put(ret)

            time.sleep(1)
