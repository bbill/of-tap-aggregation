#!/bin/bash

# launching Ryu SDN controller with simple_tap application and few additional apps for nice Web-UI
echo -e "\033[0;35m######## Launching \033[1mOpenFlow TAP Aggregation App\033[22m (press CTRL+C to Exit)\033[0m"
echo -e "\033[0;35m######## Open \033[1mhttp://<host>:8080/\033[22m in browser for Web GUI\033[0m"
ryu-manager --observe-links  ryu.app.rest_topology ryu.app.ws_topology \
    ryu.app.ofctl_rest ryu.app.gui_topology.gui_topology simple_tap.py
