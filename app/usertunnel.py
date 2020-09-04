'''
Created on May 13, 2019

@author: Tim Kreuzer
'''

from flask import request
from flask_restful import Resource
from flask import current_app as app
from threading import Thread

from app import utils_common, utils_db, utils_file_loads, tunnel_communication

"""
If a user logs out, but it's JupyterLabs should remaing running, we kill the tunnels from J4J_Tunnel to the JupyterLabs.
If it logs in again, we rebuild all tunnel.
This class should not alter any database.  
"""

class UserTunnelHandler(Resource):
    # Header:
    #   username
    def post_thread(self, app_logger, uuidcode, request_headers, app_urls, app_database):
        username = request_headers.get('username')
        app_logger.debug("uuidcode={} - Restore tunnels from database for {}".format(uuidcode, username))
        try:
            serverinfos = utils_db.get_serverinfos_for_user(app_logger, uuidcode, username, app_database)
        except:
            app_logger.exception("uuidcode={} - Could not collect serverinfos for {}. Bugfix required.".format(uuidcode, username))
        
        tunnel_header = {'Intern-Authorization': utils_file_loads.get_j4j_tunnel_token(),
                         'uuidcode': uuidcode}

        for servername, system, hostname, port, tunnelup in serverinfos:
            if tunnelup.lower() == 'true':
                app_logger.debug("uuidcode={} - Tunnel for {} is already running. Skip this one".format(uuidcode, servername))
                continue
            tunnel_data = {'account': servername,
                           'system': system,
                           'hostname': hostname,
                           'port': port}
            try:
                tunnel_communication.j4j_start_tunnel(app_logger,
                                                      uuidcode,
                                                      app_urls.get('tunnel', {}).get('url_tunnel'),
                                                      tunnel_header,
                                                      tunnel_data)
                utils_db.set_tunnelup(app_logger, uuidcode, servername, app_database, "true")
            except:
                app_logger.exception("uuidcode={} - Could not rebuild tunnel for server {}. Bugfix required".format(uuidcode, servername))
        
    
    def delete_thread(self, app_logger, uuidcode, request_headers, app_urls, app_database):
        username = request_headers.get('username')
        app_logger.debug("uuidcode={} - Delete tunnels from database for {}".format(uuidcode, username))
        try:
            servernames = utils_db.get_servername_tunnelup_for_user(app_logger, uuidcode, username, app_database)
        except:
            app_logger.exception("uuidcode={} - Could not collect serverinfos for {}. Bugfix required.".format(uuidcode, username))
        

        for servername, tunnelup in servernames:
            if tunnelup.lower() == 'false':
                app_logger.debug("uuidcode={} - Tunnel for {} is already down. Skip this one".format(uuidcode, servername))
                continue
            # Kill the tunnel
            tunnel_info = { "servername": servername }
            try:
                app_logger.debug("uuidcode={} - Close ssh tunnel".format(uuidcode))
                tunnel_communication.close(app_logger,
                                           uuidcode,
                                           app_urls.get('tunnel', {}).get('url_tunnel'),
                                           tunnel_info)
                utils_db.set_tunnelup(app_logger, uuidcode, servername, app_database, "false")
            except:
                app_logger.exception("uuidcode={} - Could not rebuild tunnel for server {}. Bugfix required".format(uuidcode, servername))
    
    def post(self):
        try:
            # Track actions through different webservices.
            uuidcode = request.headers.get('uuidcode', '<no uuidcode>')
            app.log.info("uuidcode={} - Activate User tunnels".format(uuidcode))
            app.log.trace("uuidcode={} - Headers: {}".format(uuidcode, request.headers))
            app.log.trace("uuidcode={} - Json: {}".format(uuidcode, request.json))
    
            # Check for the J4J intern token
            utils_common.validate_auth(app.log,
                                       uuidcode,
                                       request.headers.get('intern-authorization', None))
    
            app.log.debug("uuidcode={} - Start Thread to communicate with j4j_tunnel".format(uuidcode))
            request_headers = {}
            for key, value in request.headers.items():
                if 'Token' in key: # refresh, jhub, access
                    key = key.replace('-', '_')
                request_headers[key.lower()] = value
            if not request_headers.get('tokenurl', None):
                request_headers['tokenurl'] = "https://unity-jsc.fz-juelich.de/jupyter-oauth2/token"
            if not request_headers.get('authorizeurl', None):
                request_headers['authorizeurl'] = "https://unity-jsc.fz-juelich.de/jupyter-oauth2-as/oauth2-authz"
            app.log.trace("uuidcode={} - New Headers: {}".format(uuidcode, request_headers))
            t = Thread(target=self.post_thread,
                       args=(app.log,
                             uuidcode,
                             request_headers,
                             app.urls,
                             app.database))
            t.start()
        except:
            app.log.exception("Jobs.post failed. Bugfix required")
        return '', 202

    def delete(self):
        try:
            # Track actions through different webservices.
            uuidcode = request.headers.get('uuidcode', '<no uuidcode>')
            app.log.info("uuidcode={} - Delete Server".format(uuidcode))
            app.log.trace("uuidcode={} - Headers: {}".format(uuidcode, request.headers))
    
            # Check for the J4J intern token
            utils_common.validate_auth(app.log,
                                       uuidcode,
                                       request.headers.get('intern-authorization', None))
            request_headers = {}
            for key, value in request.headers.items():
                if 'Token' in key: # refresh, jhub, access
                    key = key.replace('-', '_')
                request_headers[key.lower()] = value
            if not request_headers.get('tokenurl', None):
                request_headers['tokenurl'] = "https://unity-jsc.fz-juelich.de/jupyter-oauth2/token"
            if not request_headers.get('authorizeurl', None):
                request_headers['authorizeurl'] = "https://unity-jsc.fz-juelich.de/jupyter-oauth2-as/oauth2-authz"
            app.log.debug("uuidcode={} - Start Delete Thread".format(uuidcode))
            t = Thread(target=self.delete_thread,
                       args=(app.log,
                             uuidcode,
                             request_headers,
                             app.urls,
                             app.database))
            t.start()
        except:
            app.log.exception("Jobs.delete failed. Bugfix required")
        return '', 202
