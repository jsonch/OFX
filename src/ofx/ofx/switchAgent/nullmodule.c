extern int switchListenPort;
int handle_packet(unsigned char * ethpkt, unsigned char * ippkt, int pktsize){
    return 0;
}
int module_startup(){
	dprint("null module startup.\n");
	return 1;
}
int handle_message(struct ofxDpHeader * msgHeader, unsigned char* msg){
	return 1;
}
