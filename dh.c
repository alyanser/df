#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

BIO * send_req(BIO * bio, const char * key_to_request, const char * contact_id){
	char request[1024];
	snprintf(request, sizeof(request), "GET /%s?contact_id=%s\n", key_to_request, contact_id);

	BIO_write(bio, request, strlen(request));

	char response[1024];
	const int recv_len = BIO_read(bio, response, sizeof(response));

	if(recv_len <= 0){
		return NULL;
	}

	response[recv_len] = '\0';
	return BIO_new_mem_buf(response, recv_len);
}

int user_session_setup(const char * server_addr, const char * contact_id){
	SSL_library_init();
	SSL_CTX * ctx = SSL_CTX_new(TLS_client_method());
	SSL * ssl;
	BIO * bio = BIO_new_ssl_connect(ctx);
	BIO_get_ssl(bio, &ssl);
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
	BIO_set_conn_hostname(bio, server_addr);

	if(BIO_do_connect(bio) <= 0){
		return -1;
	}

	BIO * contact_pub_key = send_req(bio, "pub_identity_key", contact_id);

	if (!contact_pub_key){
		return -1;
	}

	BIO_free_all(bio);
	SSL_CTX_free(ctx);
	return 0;
}

int main(int argc, char ** argv){

	if(argc < 3){
		fprintf(stderr, "usage: %s server_address contact_name", argv[0]);
		return 1;
	}

	if(user_session_setup(argv[1], argv[2]) < 0){
		return 1;
	}
}
