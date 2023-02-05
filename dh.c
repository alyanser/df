#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <signal_protocol.h>
#include <key_helper.h>

int main(int argc, char ** argv){

	// if(argc < 3){
		// printf("usage: %s server_address contact_name", argv[0]);
		// return 1;
	// }

	srand(time(NULL));

	signal_context * global_context;

	if(signal_context_create(&global_context, 0) < 0){
		fprintf(stderr, "could not set global context for signal. aborting...");
		return 1;
	}

	ratchet_identity_key_pair *identity_key_pair;
	uint32_t registration_id;
	signal_protocol_key_helper_pre_key_list_node *pre_keys_head;
	session_signed_pre_key *signed_pre_key;

	signal_protocol_key_helper_generate_identity_key_pair(&identity_key_pair, global_context);
	signal_protocol_key_helper_generate_registration_id(&registration_id, 0, global_context);
	signal_protocol_key_helper_generate_pre_keys(&pre_keys_head, 0, 100, global_context);
	signal_protocol_key_helper_generate_signed_pre_key(&signed_pre_key, identity_key_pair, 5, 0, global_context);

	signal_context_destroy(global_context);
}
