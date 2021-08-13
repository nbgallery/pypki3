HOSTNAME := $(shell hostname -f)

all: signuser signserver signuser_nopass signserver_nopass user_combined user_combined_nopass user_p12 user_p12_nopass

cacsrjson:
	sed 's/HOSTNAME/'`hostname -f`'/' csr.json.orig > csr.json

ca: cacsrjson
	cfssl genkey -initca csr.json | cfssljson -bare ca

userkey: ca
	openssl genrsa -aes128 -passout pass:userpass -out user-priv-key.pem 2048

userkey_nopass: ca
	openssl genrsa -out user-priv-key-nopass.pem 2048

serverkey: ca
	openssl genrsa -aes128 -passout pass:serverpass -out server-priv-key.pem 2048

serverkey_nopass: ca
	openssl genrsa -out server-priv-key-nopass.pem 2048

usercsr: userkey
	openssl req -new -sha256 -passin pass:userpass -key user-priv-key.pem -out user.csr -subj "/C=US/ST=Colorado/L=Denver/O=nbgallery/OU=WWW/CN=user"

usercsr_nopass: userkey_nopass
	openssl req -new -sha256 -key user-priv-key-nopass.pem -out user_nopass.csr -subj "/C=US/ST=Colorado/L=Denver/O=nbgallery/OU=WWW/CN=user"

servercsr: serverkey
	openssl req -new -sha256 -passin pass:serverpass -key server-priv-key.pem -out server.csr -subj "/C=US/ST=Colorado/L=Denver/O=nbgallery/OU=WWW/CN=$(HOSTNAME)"

servercsr_nopass: serverkey_nopass
	openssl req -new -sha256 -key server-priv-key-nopass.pem -out server_nopass.csr -subj "/C=US/ST=Colorado/L=Denver/O=nbgallery/OU=WWW/CN=$(HOSTNAME)"

signuser: usercsr
	cfssl sign -ca ca.pem -ca-key ca-key.pem user.csr | cfssljson -bare user-pub-key

signuser_nopass: usercsr_nopass
	cfssl sign -ca ca.pem -ca-key ca-key.pem user_nopass.csr | cfssljson -bare user-pub-key-nopass

signserver: servercsr
	cfssl sign -ca ca.pem -ca-key ca-key.pem server.csr | cfssljson -bare server-pub-key

signserver_nopass: servercsr_nopass
	cfssl sign -ca ca.pem -ca-key ca-key.pem server_nopass.csr | cfssljson -bare server-pub-key-nopass

user_combined: signuser
	cp user-priv-key.pem user-combined.pem
	cat user-pub-key.pem >> user-combined.pem

user_combined_nopass: signuser_nopass
	cp user-priv-key-nopass.pem user-combined-nopass.pem
	cat user-pub-key-nopass.pem >> user-combined-nopass.pem

user_p12: signuser
	openssl pkcs12 -export -out user.p12 -inkey user-priv-key.pem -in user-pub-key.pem -passin pass:userpass -passout pass:userpass

user_p12_nopass: signuser_nopass
	openssl pkcs12 -export -out user_nopass.p12 -inkey user-priv-key-nopass.pem -in user-pub-key-nopass.pem -nodes -passout pass:

clean:
	rm *.csr *.pem *.p12
