
web:
	./avredweb.py


docker-build:
	podman build -t avred .


# make docker-start server=http://1.1.1.1:1234
docker-start:
	podman run -p 9001:5000 -e "server=$(server)" --name avred -d avred

# make docker-start-mount server=http://1.1.1.1:1234
docker-start-mount:
	podman run -p 9001:5000 -e "server=$(server)" v $(HOME)/avred-uploads:/opt/avred/app/upload/ --name avred -d avred

