#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <deque>

#include <iostream>

#include "Minet.h"
#include "tcpstate.h"

using std::cout;
using std::endl;
using std::cerr;
using std::string;
using std::deque;



Packet createPacket(Connection c, const unsigned int &id, const unsigned int &seqNum, const unsigned int &ackNum, const unsigned short &winsize, const unsigned char &headerlen, const unsigned int &flags, const char *data, const size_t datalength)
{
	Packet new_packet(data, datalength);
								//IP Header
	IPHeader new_iph;
	new_iph.SetProtocol(IP_PROTO_TCP);
	new_iph.SetSourceIP(c.src);
	new_iph.SetDestIP(c.dest);
	new_iph.SetTotalLength(TCP_HEADER_BASE_LENGTH+IP_HEADER_BASE_LENGTH);
	new_iph.SetID(id);
	new_packet.PushFrontHeader(new_iph);
							//TCP Header
	TCPHeader new_tcph;
	new_tcph.SetSourcePort(c.srcport, new_packet);
	new_tcph.SetDestPort(c.destport, new_packet);
	new_tcph.SetHeaderLen(headerlen, new_packet);							
	new_tcph.SetFlags(flags, new_packet);							
	new_tcph.SetSeqNum(seqNum, new_packet);
	new_tcph.SetAckNum(ackNum, new_packet);
	new_tcph.SetWinSize(winsize, new_packet);								
	//new_tcph.SetUrgentPtr(upoint, new_packet);
	new_packet.PushBackHeader(new_tcph);

	cout << "NEW PACKET: " << new_packet << endl << endl;
	cout << "NEW PACKET: IP HEADER IS: " << new_iph << endl << endl;
	cout << "NEW PACKET: TCP HEADER IS: " << new_tcph << endl << endl << endl;

	return new_packet;


}

int main(int argc, char *argv[])
{
		MinetHandle mux, sock;

		MinetInit(MINET_TCP_MODULE);
		Connection correct;
		IPAddress default_IP("0.0.0.0");
		correct.src = default_IP;
		correct.srcport = 0x0000;
		int timeout = 10;
	 
 	 //experimental variable
		ConnectionList<TCPState> clist;

		mux=MinetIsModuleInConfig(MINET_IP_MUX) ? MinetConnect(MINET_IP_MUX) : MINET_NOHANDLE;
		sock=MinetIsModuleInConfig(MINET_SOCK_MODULE) ? MinetAccept(MINET_SOCK_MODULE) : MINET_NOHANDLE;

		if (MinetIsModuleInConfig(MINET_IP_MUX) && mux==MINET_NOHANDLE) {
		MinetSendToMonitor(MinetMonitoringEvent("Can't connect to mux"));
		return -1;
		}

		if (MinetIsModuleInConfig(MINET_SOCK_MODULE) && sock==MINET_NOHANDLE) {
		MinetSendToMonitor(MinetMonitoringEvent("Can't accept from sock module"));
		return -1;
		}

		MinetSendToMonitor(MinetMonitoringEvent("tcp_module handling TCP traffic"));
		srand(time(NULL));
		MinetEvent event;
		while (MinetGetNextEvent(event,timeout)==0) {
		// if we received an unexpected type of event, print error
		//cout << "MUX is: "<< mux << endl;
		//cout << "timeout " << timeout-- << endl;
		//out << "SOCK is: " << sock << endl;
		//cout << "EVENT is: " << event.handle << endl;
		if (timeout == -1)
		{
			cout << "TIMEOUT TIMEOUT " << endl;
			ConnectionList<TCPState>::iterator cs;
			for ( cs = clist.begin(); cs != clist.end(); cs++)
			{
				if ((*cs).state.GetState() == CLOSED)
				{
					cout << "Erased! " << endl;
					clist.erase(cs);
				}

				cout << "Talking to Sock" << endl;
				SockRequestResponse repl;
				repl.connection = (*cs).connection;
				repl.type = CLOSE;
				repl.bytes = 0;
				repl.error = EOK;
				MinetSend(sock, repl);
			}
		}
		else if (event.eventtype!=MinetEvent::Dataflow || event.direction!=MinetEvent::IN) {
			MinetSendToMonitor(MinetMonitoringEvent("Unknown event ignored."));
			// if we received a valid event from Minet, do processing
		} 
		else {
			//	Data from the IP layer below	//
			timeout = 10;
			if (event.handle==mux) {

				unsigned short len;
	
				//Given variables
			Packet p;
			MinetReceive(mux,p);
			unsigned tcphlen=TCPHeader::EstimateTCPHeaderLength(p);

				//Parse packet to TCP and IP headers
	 			p.ExtractHeaderFromPayload<TCPHeader>(tcphlen);
			IPHeader ipl=p.FindHeader(Headers::IPHeader);
			TCPHeader tcph=p.FindHeader(Headers::TCPHeader);
	

				//Set up new connection to send new packet
				bool checksumok = tcph.IsCorrectChecksum(p);
				Connection c;
				//unsigned int seqnum, acknum;
				//unsigned char flags = 0;
	
				//setting up new conection
				ipl.GetDestIP(c.src);
				ipl.GetSourceIP(c.dest);
				ipl.GetProtocol(c.protocol);
				tcph.GetSourcePort(c.destport);
				tcph.GetDestPort(c.srcport);


				
				cout << "Connection: " << c << endl;
				cout << "CLIST: " << clist << endl;	
				//Set up Connections List
				ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);
				
				//Check to see if Connection is the last connection. If not, then write a WRITE request to SOCK.
				//
				//IMPORTANT: The WRITE request to sock will then allow the SOCK to write TCP Packet and send to MUX.
				if (cs != clist.end()) {
				
					//GET TCP HEADER LENGTH
					//
					
					unsigned char hlen;
					tcph.GetHeaderLen(hlen);
					len = static_cast<unsigned>(hlen);

					len -= TCP_HEADER_BASE_LENGTH;
					Buffer &data = p.GetPayload().ExtractFront(len);
					//SockRequestResponse write(WRITE, (*cs).connection, data, len, EOK);
					cout << "This is data: "<< data << endl;
					if(!checksumok){
						//MinetSendToMonitor(MinetMonitoringEvent("forwarding packet to sock even though checksum failed"));
					}
					cout << "STATE: "<< (*cs).state.GetState()	<< endl;
					//MinetSend(sock, write);


					//Parse the Packet Flags
					//
					unsigned char o_flags;
					tcph.GetFlags(o_flags);
					unsigned int old_ack;
					unsigned int new_ack;
					unsigned int old_seq;
					unsigned int new_seq;
					unsigned int winsize = 14600;
					unsigned int id = rand() % 10000;
					unsigned char new_hlen = 5;
					unsigned short upoint = 0;
					unsigned int flags;
					
					tcph.GetSeqNum(old_seq);
					tcph.GetAckNum(old_ack);
					new_ack = old_seq+1;

					cout << "This is old_seq: " << old_seq << endl;
					cout << "This is old_ack: " << old_ack << endl;
		
					switch ((*cs).state.GetState()){
						case LISTEN:
						{
							if (static_cast<unsigned>(o_flags) == 2) { //|| static_cast<unsigned>(o_flags) == 4){
								Buffer data("", 0);
								new_seq = rand() % 50000;
								
								
								
								(*cs).state.SetState(SYN_RCVD);

							/*/(*cs).state.SetLastAcked(old_ack - 1);
								(*cs).state.SetLastSent(new_seq);
								(*cs).state.SetLastRecvd(old_seq);

								cout << "LAST ACKED: " << (*cs).state.last_acked << endl;
								cout << "LAST SENT: " << (*cs).state.last_sent << endl;
								cout << "LAST RECVD: " << (*cs).state.last_recvd << endl;

								clist.push_back(*cs);*/
								//Send packet to mux
								
								Packet new_packet;
								
								IPHeader new_iph;
								new_iph.SetProtocol(IP_PROTO_TCP);
								new_iph.SetSourceIP((*cs).connection.src);
								new_iph.SetDestIP((*cs).connection.dest);
								new_iph.SetTotalLength(TCP_HEADER_BASE_LENGTH+IP_HEADER_BASE_LENGTH);
								new_iph.SetID(id);
								new_packet.PushFrontHeader(new_iph);

								//TCP Header
								TCPHeader new_tcph;
								new_tcph.SetSourcePort((*cs).connection.srcport, new_packet);
								new_tcph.SetDestPort((*cs).connection.destport, new_packet);
								new_tcph.SetHeaderLen(TCP_HEADER_BASE_LENGTH, new_packet);
								new_tcph.SetFlags(0x12, new_packet);
								new_tcph.SetSeqNum(new_seq, new_packet);
								new_tcph.SetAckNum(new_ack, new_packet);
								new_tcph.SetWinSize(winsize, new_packet);
								new_tcph.SetHeaderLen(new_hlen, new_packet);
								new_tcph.SetUrgentPtr(upoint, new_packet);
								new_packet.PushBackHeader(new_tcph);	
								//send packet
								cout << "NEW PACKET: " << new_packet << endl << endl;
								cout << "NEW PACKET: IP HEADER IS: " << new_iph << endl << endl;
								cout << "NEW PACKET: TCP HEADER IS: " << new_tcph << endl << endl << endl;
														
								
								cout << "OLD PACKET: " << p << endl << endl;
								cout << "TCP Packet: IP Header is "<<ipl <<	endl << endl;
								cout << "TCP Header is "<<tcph	<< endl << endl;								//send packet
								
								MinetSend(mux, new_packet);

							}
						}
						break;
						case SYN_SENT:
						{	
							cout << "SYN SENT" << endl << endl;
							cout << "TCP Header is "<<tcph	<< endl << endl;
							if ( (static_cast<unsigned>(o_flags) == 0x12) && ((*cs).state.GetLastSent() == (old_ack - 1))){
								cout << "GOT SYNACK" << endl;
								new_seq = old_ack;
								(*cs).state.SetState(ESTABLISHED);

								(*cs).state.SetLastSent(new_seq);
								cout << "This is last sent: " << (*cs).state.GetLastSent();
								(*cs).state.SetLastAcked(old_ack);
								cout << "This is last acked: " << (*cs).state.GetLastAcked();
								(*cs).state.SetLastRecvd(old_seq);
								cout << "This is last received: " << (*cs).state.GetLastRecvd();

						
								Packet new_packet;
								
								IPHeader new_iph;
								new_iph.SetProtocol(IP_PROTO_TCP);
								new_iph.SetSourceIP((*cs).connection.src);
								new_iph.SetDestIP((*cs).connection.dest);
								new_iph.SetTotalLength(TCP_HEADER_BASE_LENGTH+IP_HEADER_BASE_LENGTH);
								new_iph.SetID(id);
								new_packet.PushFrontHeader(new_iph);

								//TCP Header
								TCPHeader new_tcph;
								new_tcph.SetSourcePort((*cs).connection.srcport, new_packet);
								new_tcph.SetDestPort((*cs).connection.destport, new_packet);
								new_tcph.SetHeaderLen(TCP_HEADER_BASE_LENGTH, new_packet);
								new_tcph.SetFlags(0x10, new_packet);
								new_tcph.SetSeqNum(new_seq, new_packet);
								new_tcph.SetAckNum(new_ack, new_packet);
								new_tcph.SetWinSize(winsize, new_packet);
								new_tcph.SetHeaderLen(new_hlen, new_packet);
								new_tcph.SetUrgentPtr(upoint, new_packet);
								new_packet.PushBackHeader(new_tcph);	
								//send packet
								cout << "NEW PACKET: " << new_packet << endl << endl;
								cout << "NEW PACKET: IP HEADER IS: " << new_iph << endl << endl;
								cout << "NEW PACKET: TCP HEADER IS: " << new_tcph << endl << endl << endl;
								MinetSend(mux, new_packet);


								cout << "OLD PACKET: " << p << endl << endl;
								cout << "TCP Packet: IP Header is "<<ipl <<	endl << endl;
								cout << "TCP Header is "<<tcph	<< endl << endl;

								

								//SockRequestResponse write(WRITE, (*cs).connection,0, EOK);
								SockRequestResponse repl;
								repl.type = WRITE;
								repl.connection = (*cs).connection;
								repl.bytes = 0;
								repl.error = EOK;
								MinetSend(sock,repl);
								//MinetSend(sock, write);
							}
						}
						break;
						case SYN_RCVD:
						{ //need to account for case where there is actual data piggy backed to this
							cout << static_cast<unsigned>(o_flags) << endl;
							if(static_cast<unsigned>(o_flags) == 16){
								new_seq = old_ack;
								(*cs).state.SetState(ESTABLISHED);
								Buffer data("", 0);
								cout << "RUNNING" << endl;
								SockRequestResponse write(WRITE, (*cs).connection, data, 0, EOK);
								MinetSend(sock, write);
							}

						}
						break;
						case ESTABLISHED:
						{
							cout << "This is flags just received: " << static_cast<unsigned>(o_flags) << endl;
							if(static_cast<unsigned>(o_flags) == 24){
								new_seq = old_ack;
								unsigned int new_len;
								tcph.GetHeaderLen(hlen);
								len = static_cast<unsigned>(hlen);
								len -= TCP_HEADER_BASE_LENGTH;
								Buffer &data = p.GetPayload().ExtractFront(len);
								SockRequestResponse write(WRITE, (*cs).connection, data, len, EOK);
								new_len = data.GetSize();
								new_ack = old_seq + new_len;
								cout << "This is data: "<< data << endl;
								cout << "DATA LENGTH: " << len << endl;
								MinetSend(sock, write);

								Packet new_packet;
								
								IPHeader new_iph;
								new_iph.SetProtocol(IP_PROTO_TCP);
								new_iph.SetSourceIP((*cs).connection.src);
								new_iph.SetDestIP((*cs).connection.dest);
								new_iph.SetTotalLength(TCP_HEADER_BASE_LENGTH+IP_HEADER_BASE_LENGTH);
								new_iph.SetID(id);
								new_packet.PushFrontHeader(new_iph);

								//TCP Header
								TCPHeader new_tcph;
								new_tcph.SetSourcePort((*cs).connection.srcport, new_packet);
								new_tcph.SetDestPort((*cs).connection.destport, new_packet);
								new_tcph.SetHeaderLen(TCP_HEADER_BASE_LENGTH, new_packet);
								new_tcph.SetFlags(0x10, new_packet);
								new_tcph.SetSeqNum(new_seq, new_packet);
								new_tcph.SetAckNum(new_ack, new_packet);
								new_tcph.SetWinSize(winsize, new_packet);
								new_tcph.SetHeaderLen(new_hlen, new_packet);
								new_tcph.SetUrgentPtr(upoint, new_packet);
								new_packet.PushBackHeader(new_tcph);	
								//send packet
								cout << "NEW PACKET: " << new_packet << endl << endl;
								cout << "NEW PACKET: IP HEADER IS: " << new_iph << endl << endl;
								cout << "NEW PACKET: TCP HEADER IS: " << new_tcph << endl << endl << endl;
								MinetSend(mux, new_packet);

							

								cout << "OLD PACKET: " << p << endl << endl;
								cout << "TCP Packet: IP Header is "<<ipl <<	endl << endl;
								cout << "TCP Header is "<<tcph	<< endl << endl;
							}
							//fin flag received
							else if(static_cast<unsigned>(o_flags) == 17 || static_cast<unsigned>(o_flags) == 1) 
							{
								new_seq = old_ack;
								Packet new_packet;

								IPHeader new_iph;
								new_iph.SetProtocol(IP_PROTO_TCP);
								new_iph.SetSourceIP((*cs).connection.src);
								new_iph.SetDestIP((*cs).connection.dest);
								new_iph.SetTotalLength(TCP_HEADER_BASE_LENGTH+IP_HEADER_BASE_LENGTH);
								new_iph.SetID(id);
								new_packet.PushFrontHeader(new_iph);

								//TCP Header
								TCPHeader new_tcph;
								new_tcph.SetSourcePort((*cs).connection.srcport, new_packet);
								new_tcph.SetDestPort((*cs).connection.destport, new_packet);
								new_tcph.SetHeaderLen(TCP_HEADER_BASE_LENGTH, new_packet);
								new_tcph.SetFlags(0x10, new_packet);
								new_tcph.SetSeqNum(new_seq, new_packet);
								new_tcph.SetAckNum(new_ack, new_packet);
								new_tcph.SetWinSize(winsize, new_packet);
								new_tcph.SetHeaderLen(new_hlen, new_packet);
								new_tcph.SetUrgentPtr(upoint, new_packet);
								new_packet.PushBackHeader(new_tcph);	
								//send packet
								cout << "NEW PACKET: " << new_packet << endl << endl;
								cout << "NEW PACKET: IP HEADER IS: " << new_iph << endl << endl;
								cout << "NEW PACKET: TCP HEADER IS: " << new_tcph << endl << endl << endl;
		


								
								MinetSend(mux, new_packet);

								cout << "OLD PACKET: " << p << endl << endl;
								cout << "TCP Packet: IP Header is "<<ipl <<	endl << endl;
								cout << "TCP Header is "<<tcph	<< endl << endl;

								SockRequestResponse repl;
								repl.type = WRITE;
								repl.connection = (*cs).connection;
								repl.bytes = 0;
								repl.error = EOK;
								MinetSend(sock,repl);
								cout << "THIS IS SOCKET REQUEST: " << repl << endl;
								(*cs).state.SetState(CLOSE_WAIT);

							}
							else if(static_cast<unsigned>(o_flags) == 0x10) {
								(*cs).state.SetLastSent(old_ack);
								(*cs).state.SetLastAcked(old_ack);
								(*cs).state.SetLastRecvd(new_seq);
								cout << "THIS IS ACK: " << tcph << endl;
							}
						}
						break;
						case LAST_ACK:
						{
							cout << "IN LAST ACK" << endl;
							cout << "This is received flag: " << static_cast<unsigned>(o_flags) << endl;
							if(static_cast<unsigned>(o_flags) == 16){
								(*cs).state.SetState(CLOSED);
								clist.erase(cs);
							}
							
						}
						break;
						case FIN_WAIT1:
						{
							cout <<"IN FIN_WAIT1, RECEIVED ACK" << endl;
							cout << "This is received flag: " << static_cast<unsigned>(o_flags) << endl;
							if(static_cast<unsigned>(o_flags) == 16){
								new_seq = old_ack;
								(*cs).state.SetState(FIN_WAIT2);
							}
						}
						case FIN_WAIT2:
						{
							new_seq = old_ack;
							Packet new_packet;

							IPHeader new_iph;
							new_iph.SetProtocol(IP_PROTO_TCP);
							new_iph.SetSourceIP((*cs).connection.src);
							new_iph.SetDestIP((*cs).connection.dest);
							new_iph.SetTotalLength(TCP_HEADER_BASE_LENGTH+IP_HEADER_BASE_LENGTH);
							new_iph.SetID(id);
							new_packet.PushFrontHeader(new_iph);

								//TCP Header
							TCPHeader new_tcph;
							new_tcph.SetSourcePort((*cs).connection.srcport, new_packet);
							new_tcph.SetDestPort((*cs).connection.destport, new_packet);
							new_tcph.SetHeaderLen(TCP_HEADER_BASE_LENGTH, new_packet);
							new_tcph.SetFlags(0x10, new_packet);
							new_tcph.SetSeqNum(new_seq, new_packet);
							new_tcph.SetAckNum(new_ack, new_packet);
							new_tcph.SetWinSize(winsize, new_packet);
							new_tcph.SetHeaderLen(new_hlen, new_packet);
							new_tcph.SetUrgentPtr(upoint, new_packet);
							new_packet.PushBackHeader(new_tcph);	
								//send packet
							cout << "NEW PACKET: " << new_packet << endl << endl;
							cout << "NEW PACKET: IP HEADER IS: " << new_iph << endl << endl;
							cout << "NEW PACKET: TCP HEADER IS: " << new_tcph << endl << endl << endl;
	


								
							MinetSend(mux, new_packet);

							cout << "OLD PACKET: " << p << endl << endl;
							cout << "TCP Packet: IP Header is "<<ipl <<	endl << endl;
							cout << "TCP Header is "<<tcph	<< endl << endl;

							(*cs).state.SetState(TIME_WAIT);

						}
						break;
						case TIME_WAIT:
						{
							sleep(30);
							(*cs).state.SetState(CLOSED);
							clist.erase(cs);

						}
						break;
					}
				}
				else {
					ConnectionToStateMapping<TCPState> tmp;
					tmp.connection = c;
					cout << "CORRECT SRC AND SRCPORT: " << correct.src <<":"<< correct.srcport << endl;
					cout << "TMP SRC AND SRCPORT: " << tmp.connection.src << ":" << tmp.connection.srcport << endl;
					if (tmp.connection.src == correct.src && tmp.connection.srcport == correct.srcport){
						tmp.state.SetState(LISTEN);
						clist.push_back(tmp);
						
						//Parse the Packet Flags
						//

						unsigned char o_flags;
						tcph.GetFlags(o_flags);
						//unsigned int old_ack;
						unsigned int new_ack;
						unsigned int old_seq;
						unsigned int new_seq;
						unsigned int winsize = 14600;
						unsigned int id = rand() % 10000;
						unsigned char hlen = 5;
						unsigned short upoint = 0;
					
						tcph.GetSeqNum(old_seq);
						new_ack = old_seq+1;
						new_seq = rand() % 50000;

						if (static_cast<unsigned>(o_flags) == 2){
							Buffer data("", 0);
							//cout << "This is data: "<< data << endl;
							//SockRequestResponse write(WRITE, c, data, 0, EOK);
							//cout << "Response to Sock: "<< write << endl;
							//MinetSend(sock, write);

							//Send packet to mux
							//
							Packet new_packet;
							//IP Header
							IPHeader new_iph;
							new_iph.SetProtocol(IP_PROTO_TCP);
							new_iph.SetSourceIP(tmp.connection.src);
							new_iph.SetDestIP(tmp.connection.dest);
							new_iph.SetTotalLength(TCP_HEADER_BASE_LENGTH+IP_HEADER_BASE_LENGTH);
							new_iph.SetID(id);
							new_packet.PushFrontHeader(new_iph);

							//TCP Header
							TCPHeader new_tcph;
							new_tcph.SetSourcePort(tmp.connection.srcport, new_packet);
							new_tcph.SetDestPort(tmp.connection.destport, new_packet);
							new_tcph.SetHeaderLen(TCP_HEADER_BASE_LENGTH, new_packet);
							new_tcph.SetFlags(0x00, new_packet);
							new_tcph.SetSeqNum(new_seq, new_packet);
							new_tcph.SetAckNum(new_ack, new_packet);
							new_tcph.SetWinSize(winsize, new_packet);
							new_tcph.SetHeaderLen(hlen, new_packet);
							new_tcph.SetUrgentPtr(upoint, new_packet);
							new_packet.PushBackHeader(new_tcph);	
							//send packet

							cout << "OLD PACKET: " << p << endl << endl;
							cout << "TCP Packet: IP Header is "<<ipl <<	endl << endl;
							cout << "TCP Header is "<<tcph	<< endl << endl;

							cout << "NEW PACKET: " << new_packet << endl << endl;
							cout << "NEW PACKET: IP HEADER IS: " << new_iph << endl << endl;
							cout << "NEW PACKET: TCP HEADER IS: " << new_tcph << endl << endl << endl;
							MinetSend(mux, new_packet);

						}
						

					}
				}

			}
		//	Data from the Sockets layer above	//
	 	 		if (event.handle==sock) {
	 	 	timeout = 10;
			SockRequestResponse s;
			MinetReceive(sock,s);
				switch (s.type) {
					case CONNECT:
					{
						//Set up TCP STATE
						ConnectionToStateMapping<TCPState> tmp;
						tmp.connection = s.connection;
						tmp.state.SetState(SYN_SENT);
						clist.push_back(tmp);

						//REPLY TO SOCK
						SockRequestResponse repl;
						repl.type = STATUS;
						repl.connection = s.connection;
						repl.bytes = 0;
						repl.error = EOK;
						MinetSend(sock,repl);

						cout << "Received Socket Request:" << s << endl << endl;
						cout << "Reply Socket Request" << repl << endl << endl;

						//Start building the SYN Packet
						int i = 0;
						while(i != 2){
							sleep(15);
							unsigned int new_ack = 0;
							unsigned int new_seq = rand() % 50000;
							unsigned int winsize = 14600;
							unsigned int id = rand() % 10000;
							unsigned char hlen = 5;
							unsigned short upoint = 0;

							Buffer data("", 0);
							Packet new_packet(data);

							ConnectionList<TCPState>::iterator cs = clist.FindMatching(s.connection);

							//IP Header
							IPHeader new_iph;
							new_iph.SetProtocol(IP_PROTO_TCP);
							new_iph.SetSourceIP(tmp.connection.src);
							new_iph.SetDestIP(tmp.connection.dest);
							new_iph.SetTotalLength(TCP_HEADER_BASE_LENGTH+IP_HEADER_BASE_LENGTH);
							new_iph.SetID(id);
							new_packet.PushFrontHeader(new_iph);

							//TCP Header
							TCPHeader new_tcph;
							new_tcph.SetSourcePort(tmp.connection.srcport, new_packet);
							new_tcph.SetDestPort(tmp.connection.destport, new_packet);
							new_tcph.SetHeaderLen(TCP_HEADER_BASE_LENGTH, new_packet);
							new_tcph.SetFlags(0x02, new_packet);
							new_tcph.SetSeqNum(new_seq, new_packet);
							new_tcph.SetAckNum(new_ack, new_packet);
							new_tcph.SetWinSize(winsize, new_packet);
							new_tcph.SetHeaderLen(hlen, new_packet);
							new_tcph.SetUrgentPtr(upoint, new_packet);
							new_packet.PushBackHeader(new_tcph);	

							//send packet
							cout << "NEW PACKET: " << new_packet << endl << endl;
							cout << "NEW PACKET: IP HEADER IS: " << new_iph << endl << endl;
							cout << "NEW PACKET: TCP HEADER IS: " << new_tcph << endl << endl << endl;
							MinetSend(mux, new_packet);
							


							if (i == 1){
								(*cs).state.SetLastSent(new_seq);
								cout << "This is last_sent: " << (*cs).state.GetLastSent() << endl;
							}

							i++;
							
						}
					}
					break;
					case ACCEPT:
					{
						SockRequestResponse repl;
						repl.type = STATUS;
						repl.connection = s.connection;
						correct = s.connection;
						cout << "THIS IS OUR CONNECTION: " << correct << endl;
						repl.bytes = 0;
						repl.error = EOK;
						MinetSend(sock,repl);
						cout << "Received Socket Request:" << s << endl << endl;
						cout << "Reply Socket Request" << repl << endl << endl;


					}
					break;
					case STATUS:
					{
						cout << "status" << endl;
					}
					break;
					case CLOSE:
					{
						cout << "TIME TO SEND FIN!" << endl;
						unsigned int winsize = 14600;
						unsigned int id = rand() % 10000;
						unsigned short upoint = 0;

						Packet p;

						//IP Header
						IPHeader iph;
						iph.SetProtocol(IP_PROTO_TCP);
						iph.SetSourceIP(s.connection.src);
						iph.SetDestIP(s.connection.dest);
						iph.SetTotalLength(TCP_HEADER_BASE_LENGTH+IP_HEADER_BASE_LENGTH);
						iph.SetID(id);
						p.PushFrontHeader(iph);


						//TCP Header
						TCPHeader tcph;
						unsigned int new_ack = 0;
						unsigned int new_seq = rand() % 50000;
						tcph.SetAckNum(new_ack, p);
						tcph.SetSeqNum(new_seq, p);
						tcph.SetSourcePort(s.connection.srcport, p);
						tcph.SetDestPort(s.connection.destport, p);
						tcph.SetHeaderLen(TCP_HEADER_BASE_LENGTH, p);
						tcph.SetWinSize(winsize, p);
						tcph.SetFlags(0x01, p);
						tcph.SetUrgentPtr(upoint, p);
						p.PushBackHeader(tcph);

						cout << "NEW PACKET: " << p << endl << endl;
						cout << "NEW PACKET: IP HEADER IS: " << iph << endl << endl;
						cout << "NEW PACKET: TCP HEADER IS: " << tcph << endl << endl << endl;
						MinetSend(mux, p);

						ConnectionList<TCPState>::iterator cs = clist.FindMatching(s.connection);
						
						if ((*cs).state.GetState() == ESTABLISHED)
						{
							(*cs).state.SetState(FIN_WAIT1);
						}
						else{
							(*cs).state.SetState(LAST_ACK);	
						}
					}
					break;
					case WRITE:
					{
						cout << "Received Socket Request:" << s << endl << endl;
						cout << "THIS IS DATA FROM APP: " << s.data << endl;
						unsigned bytes = MIN_MACRO(TCP_HEADER_MAX_LENGTH, s.data.GetSize());
						cout << "This is size of data: " << bytes << endl;
						//cout << "EXTRACTED DATA: " << s.data.ExtractFront(bytes) << endl;
						Packet p(s.data.ExtractFront(bytes));
						cout << "THIS IS PACKET P: " << p << endl;
						//Packet p;
						unsigned int winsize = 14600;
						unsigned int id = rand() % 10000;
						unsigned short upoint = 0;
						unsigned char hlen = 5; //+ ((bytes/4)+1);
						cout << "Header Length: " << hlen << endl;
						//unsigned int new_ack;
						//unsigned int new_seq;

						ConnectionList<TCPState>::iterator cs = clist.FindMatching(s.connection);	


						//IP Header
						IPHeader iph;
						iph.SetProtocol(IP_PROTO_TCP);
						iph.SetSourceIP(s.connection.src);
						iph.SetDestIP(s.connection.dest);
						iph.SetTotalLength(TCP_HEADER_BASE_LENGTH+IP_HEADER_BASE_LENGTH + bytes);
						iph.SetID(id);
						p.PushFrontHeader(iph);


						//TCP Header
						TCPHeader tcph;
						unsigned int new_ack = (*cs).state.GetLastRecvd();
						unsigned int new_seq = (*cs).state.GetLastSent();
						tcph.SetAckNum(new_ack+1, p);
						tcph.SetSeqNum(new_seq, p);
						tcph.SetSourcePort(s.connection.srcport, p);
						tcph.SetDestPort(s.connection.destport, p);
						tcph.SetHeaderLen(hlen, p);
						tcph.SetWinSize(winsize, p);
						tcph.SetFlags(0x18, p);
						tcph.SetUrgentPtr(upoint, p);
						p.PushBackHeader(tcph);

						cout << "This is new_seq: " << new_seq << endl;
						cout << "This is new_ack: " << new_ack << endl;

						(*cs).state.SetLastSent(new_seq);
						cout << "This is last_sent: " << (*cs).state.GetLastSent() << endl;
						(*cs).state.SetLastRecvd(new_ack);
						cout << "This is last_recvd: " << (*cs).state.GetLastRecvd() << endl;
						(*cs).state.SetLastAcked(new_seq);
						cout << "This is last_acked: " << (*cs).state.GetLastAcked() << endl;
			
						cout << "SENDING: " << p << endl;
						cout << "IP HEADER: "<< iph << endl;
						cout << "TCP HEADER: " << tcph <<endl;

						//Send the packet through the mux
						MinetSend(mux, p);
					
						//REPLY:
						SockRequestResponse repl;
						repl.type = STATUS;
						repl.connection = s.connection;
						repl.bytes = bytes;
						repl.error = EOK;
						MinetSend(sock, repl);
						
						cout << "Reply Socket Request" << repl << endl << endl;
					}
					break;
					default:
					{
						SockRequestResponse repl;
						repl.type = STATUS;
						repl.error = EWHAT;
						MinetSend(sock, repl);
						cout << "WHY???" << endl;
					}
				}
			}
		}
		}
	return 0;
}
