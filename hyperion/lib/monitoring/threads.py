import threading
import logging
import sys
import time
from psutil import Process, NoSuchProcess
is_py2 = sys.version[0] == '2'
if is_py2:
    import Queue as Queue
else:
    import queue as Queue


class ComponentMonitorJob(object):
    def __init__(self, pid, comp_name, host=None):
        self.pid = pid
        self.comp_name = comp_name
        self.host = host

    def run_check(self):
        if self.host:
            print("No remote monitoring implemented yet")
            return True
        else:
            try:
                proc = Process(self.pid)
                if proc.is_running():
                    return True
            except NoSuchProcess:
                pass
        return CrashEvent(self.comp_name)

    def info(self):
        return "Running check for component %s with pid %s" % (self.comp_name, self.pid)


class HostMonitorJob(object):
    def __init__(self, pid, hostname):
        self.pid = pid
        self.hostname = hostname

    def run_check(self):
        try:
            proc = Process(self.pid)
            if proc.is_running():
                return True
        except NoSuchProcess:
            pass
        return DisconnectEvent(self.hostname)

    def info(self):
        return "Running ssh host check for %s with pid %s" % (self.hostname, self.pid)


class CrashEvent(object):
    def __init__(self, comp_name):
        self.comp_name = comp_name


class DisconnectEvent(object):
    def __init__(self, hostname):
        self.hostname = hostname


class MonitoringThread(threading.Thread):
    def __init__(self, queue):
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.DEBUG)
        logger.debug("Initialized thread")
        super(MonitoringThread, self).__init__()
        self.job_queue = queue
        self.subscribed_queues = []
        self.end = False

    def kill(self):
        logger = logging.getLogger(__name__)
        logger.debug("Killing process monitoring thread")
        self.end = True

    def add_subscriber(self, queue):
        logger = logging.getLogger(__name__)
        logger.debug("Added subscriber")
        self.subscribed_queues.append(queue)

    def run(self):
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.DEBUG)
        logger.debug("Started run funtion")
        while not self.end:

            jobs = []
            # Get all enqueued jobs for this iteration
            while not self.job_queue.empty():
                mon_job = self.job_queue.get()
                logger.debug("Adding job %s to list" % mon_job.pid)
                jobs.append(mon_job)

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

            time.sleep(5)
