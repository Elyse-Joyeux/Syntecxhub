import socket
from datetime import datetime
import threading
from queue import Queue
import logging


# Logging configuration
logging.basicConfig(
    filename="scan_results.txt",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)


# prevent duplicate entries from shared variable
print_lock = threading.Lock()

host = input("Enter the host to scan(address): ")
start_port = int(input("Enter starting port: "))
end_port = int(input("Enter ending port: "))
# Translate the hostname to IPv4 address format
ip = socket.gethostbyname(host)


print("-" * 80)
print("Please wait, scanning remote host", ip)
print("Scanning ports", start_port, "to", end_port)
print("-" * 80)


# start time
t1 = datetime.now()
# port scanning 
def scan(port):

    try:

        # tcp socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        #connection to port
        result = sock.connect_ex((ip, port))
        if result == 0:

            with print_lock:
                print("\nPort %d is open ---------> " % (port))

            # log open port
            logging.info("Port %d is OPEN" % (port))

        else:

            with print_lock:
                print("\nPort %d is closed: -( " % (port))

            # log closed port
            logging.info("Port %d is CLOSED" % (port))

        sock.close()


    # handle timeout
    except socket.timeout:

        with print_lock:
            print("\nPort %d timed out" % (port))

        logging.info("Port %d TIMED OUT" % (port))


    # handle other socket errors
    except socket.error as e:

        with print_lock:
            print("\nPort %d error: %s" % (port, e))

        logging.info("Port %d ERROR: %s" % (port, e))


    # keep your original exception handling
    except:

        pass



#threader function
def threader():

    while True:

        # get a worker from the queue
        worker = q.get()
        scan(worker)
        q.task_done()



# Queue creation
q = Queue()

# create threads
for x in range(99):

    t = threading.Thread(target=threader)

    t.daemon = True

    t.start()


# add ports to the queue
for worker in range(start_port, end_port + 1):

    q.put(worker)

q.join()


# calculate end of execution time
t2 = datetime.now()


# calculate the difference
total = t2 - t1

print("-" * 80)
print("Total Scanning time:", total)
print("Results saved to scan_results.txt")
print("-" * 80)