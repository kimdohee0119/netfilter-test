all: netfilter_test

netfilter-test: netfilter-test.c
	sudo iptables -F
	sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0
	sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0
	gcc -o netfilter-test netfilter-test.c -lnetfilter_queue
