from socket import *
import os
import sys
import struct
import time
import select
import binascii
import socket

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 1


# The packet that we shall send to each router along the path is the ICMP echo
# request packet, which is exactly what we had used in the ICMP ping exercise.
# We shall use the same packet that we built in the Ping exercise

def checksum(string):
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = (string[count + 1]) * 256 + (string[count])
        csum += thisVal
        csum &= 0xffffffff
        count += 2

    if countTo < len(string):
        csum += (string[len(string) - 1])
        csum &= 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def build_packet():
    # Fill in start
    # In the sendOnePing() method of the ICMP Ping exercise ,firstly the header of our
    # packet to be sent was made, secondly the checksum was appended to the header and
    # then finally the complete packet was sent to the destination.

    # Make the header in a similar way to the ping exercise.
    # Append checksum to the header.

    # Don’t send the packet yet , just return the final packet in this function.
    # Fill in end

    # So the function ending should look like this
    myChecksum = 0
    ID = os.getpid() & 0xFFFF  # Return the current process i
    # Make a dummy header with a 0 checksum
    # struct -- Interpret strings as packed binary data
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    data = struct.pack("d", time.time())

    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(header + data)

    # Get the right checksum, and put in the header

    if sys.platform == 'darwin':
        # Convert 16-bit integers from host to network  byte order
        myChecksum = htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    packet = header + data
    return packet


def get_route(hostname):
    destAddr = gethostbyname(hostname)
    print("Tracing route to " + hostname + " [" + destAddr + "]")
    print("over a maximum of " + str(MAX_HOPS) + " hops:\n")

    timeLeft = TIMEOUT
    tracelist1 = []  # This is your list to use when iterating through each trace
    tracelist2 = []  # This is your list to contain all traces

    for ttl in range(1, MAX_HOPS):
        tracelist1.clear()
        tracelist1.append(str(ttl))
        for tries in range(TRIES):


            # Fill in start
            icmp = getprotobyname("icmp")
            #host = socket.gethostbyaddr("ip")
            # Make a raw socket named mySocket
            mySocket = socket.socket(AF_INET, SOCK_RAW, icmp)
            # Fill in end

            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)
            try:
                d = build_packet()
                mySocket.sendto(d, (hostname, 0))
                t = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                howLongInSelect = (time.time() - startedSelect)
                if whatReady[0] == []:  # Timeout
                    tracelist1.append('*')
                    tracelist1.append("Request timed out")
                    print(tracelist1)
                    # Fill in start
                    # You should add the list above to your all traces list
                    concatList1 = tracelist1[:]
                    tracelist2.append([concatList1])
                    # Fill in end
                recvPacket, addr = mySocket.recvfrom(1024)
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    tracelist1.append('*')
                    tracelist1.append("Request timed out")
                    print(tracelist1)
                    # Fill in start
                    concatList1 = tracelist1[:]
                    tracelist2.append([concatList1])
                    # You should add the list above to your all traces list
                    # Fill in end
            except timeout:
                continue

            else:
                # Fill in start
                # Fetch the icmp type from the IP packet
                types = recvPacket[20]
                # Fill in end
                try:  # try to fetch the hostname
                # Fill in start
                    a = str(recvPacket[12])
                    b = str(recvPacket[13])
                    c = str(recvPacket[14])
                    d = str(recvPacket[15])
                    routerIP = a + '.' + b + '.' + c + '.' + d
                    routerhostname = gethostbyaddr(routerIP)[0]
                except herror:  # if the host does not provide a hostname
                # Fill in start
                    routerhostname = "hostname not returnable"
                # Fill in end

                if types == 11:
                    bytes = struct.calcsize("d")
                    try:
                        timeSent = struct.unpack("d", recvPacket[56:56 + bytes])[0]
                        totalTime = str(round((timeReceived - timeSent) * 1000)) + "ms"
                    except:
                        totalTime = '*'

                    # Fill in start
                    # You should add your responses to your lists here
                    tracelist1.append(totalTime)
                    tracelist1.append(routerIP)
                    tracelist1.append(routerhostname)
                    # print("type 11; Sent: " + str(timeSent) + "; Recvd: " + str(timeReceived))
                    print(tracelist1)
                    concatList1 = tracelist1[:]
                    tracelist2.append(concatList1)
                    # Fill in end
                elif types == 3:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[56:56 + bytes])[0]
                    # Fill in start
                    # You should add your responses to your lists here
                    tracelist1.append(str(round((timeReceived - timeSent) * 1000)) + "ms")
                    tracelist1.append(routerIP)
                    tracelist1.append(routerhostname)
                    tracelist1.append("destination unreachable")
                    print(tracelist1)
                    concatList1 = tracelist1[:]
                    tracelist2.append(concatList1)
                    # Fill in end
                elif types == 0:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    # Fill in start
                    # You should add your responses to your lists here and return your list if your destination IP is met
                    tracelist1.append(str(round((timeReceived - timeSent) * 1000)) + "ms")
                    tracelist1.append(routerIP)
                    tracelist1.append(routerhostname)
                    print(tracelist1)
                    concatList1 = tracelist1[:]
                    tracelist2.append(concatList1)
                    if (routerhostname == hostname) or (routerIP == destAddr):
                        print("Destination reached in " + str(ttl) + " hops.")
                        print("")
                        print(tracelist2)
                        return tracelist2
                    print (" %d   rtt=%.0f ms %s" % (ttl,(timeReceived -timeSent)*1000, addr[0]))
                    # Fill in end
                else:
                    #Fill in start
                    #If there is an exception/error to your if statements, you should append that to your list here
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    tracelist1.append(str(round((timeReceived - timeSent) * 1000)) + "ms")
                    tracelist1.append(routerIP)
                    tracelist1.append(routerhostname)
                    tracelist1.append("unknown icmp type")
                    print(tracelist1)
                    copyOfList1 = tracelist1[:]
                    tracelist2.append([copyOfList1])
                    #Fill in end
                break
            finally:
                mySocket.close()

    print("Unable to reach destination within " + str(MAX_HOPS) + " hops.")
    print("")
    print(tracelist2)
    return tracelist2

if __name__ == '__main__':
    get_route("yahoo.com")
