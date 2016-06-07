# ipLoadBalancer

IP Load Balancer module is developed in POX SDN controller.
This modules enables the switch to distribute the requests from the clients among the servers connected to it. 
Load balancing is achieved in the network level where servers are connected.


Consider a switch has set of hosts which act as servers and set of hosts which act as clients. Requets from client
usually distributed among the servers with the special algorithm running in each servers. With this case, the load in Network
remains the same. The IP load balancer module enables the switch to distribute the requests from the clients among the servers.
Here the switch acts as load balancer and the load is distributed in the network level.
