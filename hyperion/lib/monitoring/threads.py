from threading import Thread, Lock
import logging
import sys
import time
import hyperion.lib.util.config as config
import hyperion.lib.util.events as events
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

    def __init__(self, pid, comp_id):
        """Initializes component monitoring job.

        :param pid: Process id of the component
        :type pid: int
        :param comp_id: Name of the component
        :type comp_id: str
        """
        self.pid = pid
        self.comp_id = comp_id
        self.error_msg = "Component '%s' crashed!" % comp_id

    def run_check(self):
        """You need to override this function in monitoring subclasses. It is called in the main monitoring thread.

        :return: True on a successful check, otherwise a CrashEvent is generated
        :rtype: bool or CrashEvent
        """
        raise NotImplementedError


class CancellationJob(ComponentMonitorJob):
    def run_check(self):
        # Is never called here
        pass

    def __init__(self, pid, comp_id):
        """Creates a cancellation job for a component.

        :param pid: Process id of the component
        :type pid: int
        :param comp_id: Name of the component
        :type comp_id: str
        """
        super(CancellationJob, self).__init__(pid, comp_id)


class LocalComponentMonitoringJob(ComponentMonitorJob):
    """Class that represents a local component monitoring job."""

    def __init__(self, pid, comp_id):
        """Creates a monitoring job for a local component.

        :param pid: Process id of the component
        :type pid: int
        :param comp_id: Name of the component
        :type comp_id: str
        """
        super(LocalComponentMonitoringJob, self).__init__(pid, comp_id)

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
        return events.CrashEvent(self.comp_id)

    def info(self):
        """Generate a status information for the job describing what is being monitored.

        :return: Information about this job
        :rtype: str
        """

        return "Running check for local component %s with pid %s" % (self.comp_id, self.pid)


class RemoteComponentMonitoringJob(ComponentMonitorJob):
    """Class that represents a remote component monitoring job."""

    def __init__(self, pid, comp_id, hostname, host_status):
        """Creates a remote component monitoring job.

        :param pid: Process id on the remote machine
        :type pid: int
        :param comp_id: Name of the monitored component
        :type comp_id: str
        :param hostname: Name of the host running the component
        :type hostname: str
        """

        super(RemoteComponentMonitoringJob, self).__init__(pid, comp_id)
        self.hostname = hostname
        self.host_status = host_status

    def run_check(self):
        """Runs a check if a remote process is still running.

        :return: True if the component is still running or the host is not reachable, otherwise a ``RemoteCrashEvent`` is generated.
        :rtype: bool or events.CrashEvent
        """

        if self.host_status.get(self.hostname):
            cmd = 'ssh -F %s %s "ps -p %s" 2> /dev/null 1> /dev/null' % (config.CUSTOM_SSH_CONFIG_PATH, self.hostname, self.pid)
            if call(cmd, shell=True) == 0:
                return True
            else:
                return events.CrashEvent(self.comp_id, True)
        # Return true because no information can be retrieved. The connection to the host has to be reestablished first.
        return True

    def info(self):
        """Generate a status information for the job describing what is being monitored.

        :return: Information about this job
        :rtype: str
        """

        return "Running check for remote component %s with pid %s on host %s" % (self.comp_id, self.pid,
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
        self.error_msg = "Lost connection to '%s'!" % hostname

    def run_check(self):
        try:
            proc = Process(self.pid)
            if proc.is_running():
                return True
        except NoSuchProcess:
            pass

        self.host_lock.acquire()
        self.host_status[self.hostname] = None
        self.host_lock.release()

        return events.DisconnectEvent(self.hostname)

    def info(self):
        return "Running ssh host check for %s with pid %s" % (self.hostname, self.pid)


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
        logger.debug("Adding subscriber")
        self.subscribed_queues.append(queue)

    def remove_subscriber(self, queue):
        """Remove a subscriber from the list of queues to send notifications to.

        :param queue: Unsubscribing queue that will get no notifications by this thread anymore
        :type queue: Queue.Queue
        :return: None
        """
        logger = logging.getLogger(__name__)
        logger.debug("Removing subscriber")
        self.subscribed_queues.remove(queue)

    def run(self):
        """Starts the monitoring thread.

        :return: None
        """

        logger = logging.getLogger(__name__)
        logger.setLevel(logging.DEBUG)
        logger.debug("Started run funtion")
        while not self.end:

            comp_jobs = []
            cancellations = []
            jobs = []
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
            remove = []
            for mon_job in cancellations:
                for comp_job in comp_jobs:
                    if mon_job.comp_id is comp_job.comp_id:
                        remove.append(comp_job)
            [comp_jobs.remove(job) for job in remove]

            # Reorder job list to first check the hosts, then check the components because this makes sense
            jobs.extend(comp_jobs)
            for mon_job in jobs:
                #logger.debug(mon_job.info())
                ret = mon_job.run_check()
                if ret is True:
                    #logger.debug("S'all good man")
                    # If job is ok, put it back for the next iteration
                    self.job_queue.put(mon_job)
                else:
                    # If job is not ok, notify subscribers
                    logger.error(mon_job.error_msg)
                    logger.debug("Notifying mon subscribers about failed check")
                    for subscriber in self.subscribed_queues:
                        subscriber.put(ret)

            time.sleep(1)
