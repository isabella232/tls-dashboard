# tls-dashboard
A dashboard written in JavaScript &amp; HTML to check the remaining time before a TLS certificate expires. A combination of a Node module and an HTML/CSS/JS webpage to display the info. 

**Version:** 1.1.0

## Node Setup
### `node_app/config.js`
Contains the configuration variables for the node script.  

* `connection_timeout` - The time in milliseconds that node should leave a connection open without response after the socket has been assigned. Once the timeout expires, node emits a `timeout` event and aborts the connection request. Default is 5000ms.  
* `output_file`  
  * `path` - The path to the directory that you want the output file written to. Can be relative or absolute, requires a trailing `/`, and defaults to the `../web_service/js/tls-dashboard/` directory. If you move the contents of the `./web_service` directory, make sure you update this path.  
  * `name` - The name of the output file. This typically doesn't need to be changed, but if you do change it, you'll also need to change the filename in `index.html` at line 14.  


### `node_app/monitored_hosts.js`
Contains an array of all of the hostnames that you want to monitor. 

### `node_app/get_cert_info.js`
This module performs the actual HTTPS connection and evaluation of the peer certificates, and outputs the results into a flat file. There are no configuration changes needed in this file. To get things going, you can either:  

1. Run the script manually whenever you need to update your dashboard by calling `node get_cert_info.js`; or   
2. Set up the script to run on a cronjob

It's entirely up to you how you want to handle it. 

## Python Setup
### `python_app/config.json`
Contains the configuration variables for the python script.

* `connection_timeout` - The time in milliseconds that node should leave a connection open without response after the socket has been assigned. Once the timeout expires, node emits a `timeout` event and aborts the connection request. Default is 5000ms.  
* `output_file`  
  * `path` - The path to the directory that you want the output file written to. Can be relative or absolute, requires a trailing `/`, and defaults to the `../web_service/js/tls-dashboard/` directory. If you move the contents of the `./web_service` directory, make sure you update this path.  
  * `name` - The name of the output file. This typically doesn't need to be changed, but if you do change it, you'll also need to change the filename in `index.html` at line 14.  

### `python_app/monitored_hosts.json`
Contains an array of all of the hostnames that you want to monitor. 

### `python_app/get_cert_info.py`
This module performs the actual HTTPS connection and evaluation of the peer certificates, and outputs the results into a flat file. There are no configuration changes needed in this file. To get things going, you can either:  
1. Run teh script manually whenever you need to update your dashboard by calling `python3 get_cert_info.py`
2. Set up the script to run on a cronjob

It's entirely up to you how you want to handle it.

## Web Service Setup
To get the web service started, you'll need to either move the contents of the `web_service` directory to somewhere in your web site's path, or create a symlink from the web site path back to the directory. If you move the contents, please update the `output_file.path` config value. These are static files with relative links, so other than moving them/pointing the server to them, there's nothing else required for you to do. 

## Example
Take a look at a live example page [here on GitLab][1]. Screenshots below. 

![Example dashboard](https://raw.githubusercontent.com/cmrunton/tls-dashboard/master/screenshot.png)  
![Example dashboard](https://raw.githubusercontent.com/cmrunton/tls-dashboard/master/screenshot_2.png)  

## TODO
1. Database integration?  
2. Slack integration?  

## Dependencies
The node module has no dependencies external to the node core. The following dependencies are provided for the web service to render properly.

* jQuery v2.2.2  
* Handlebars v4.0.5  
* Bootstrap v4.0.0-alpha (CSS only)  

[1]:https://craine.gitlab.io/tls-dashboard/