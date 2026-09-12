import socket 
from datetime import datetime
import threading
from queue import Queue

#prevent duplicate entries from shared variable
print_lock = threading.Lock()

#the host to scan
host = input("Enter the host to scan(address): ")
ip = socket.gethostbyname(host) #translate the hostname to ipv4 address format

print("-" * 80)
print("Please wait, scanning remote host", ip)
print("-" * 80)

#tart time
t1 = datetime.now()

#port scanning code
def scan(port):
    try:
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #create sock stream
        result = sock.connect_ex((ip, port))
        if result == 0:
            #if a socket is listening it will print out the port number
            print("\n Port %d is open ---------> " %(port))
            sock.close()

        else:
            print("\n Port %d is close: -( " %(port))

    except:
        pass


#create threader function
def threader():
    while True:
        worker = q.get() #get an worker from teh queue
        scan(worker) #scan is a funtion  & it run the job with the variable worker in queue
        q.task_done() #complete with the job

#queue creation
q = Queue()

#writing for loop for number of thread to allow
for x in range(99):
    t = threading.Thread(target=threader)
    t.daemon=True
    t.start()

for worker in range(1, 100):
    q.put(worker)

#threader will join after thread termination
q.join()




#calculate end of exec time
t2 = datetime.now()

#calculate the difference
total = t2 -t1

#print the difference
print("Total Scanning time: ", total)