FROM debian:bookworm-slim
WORKDIR /opt
RUN apt-get update && \
	apt-get install -y iputils-ping bind9-dnsutils git build-essential iodine dns2tcp ruby ruby-dev && \
	rm -rf /var/lib/apt/lists/* && \
	git clone https://github.com/iagox86/dnscat2.git && \
	cd /opt/dnscat2/client/ && \
	make && \
	cd /opt/dnscat2/server/ && \
	gem install bundler && \
	bundle install
