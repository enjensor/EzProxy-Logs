#!/usr/bin/env python
# coding: utf-8

# # EzProxy Fails : Daily

# ***This runs best in Jupyter, either on a local machine or on a server you have file access to.*** 
# 
# To review all users failing to access EzProxy, make sure you place the audit logs into the /data folder and that they are named in the syntax of "YYYYMMDD.txt" (for example, "20190314.txt"). These audit files are usually in the /audit sub-folder of your EzProxy application folder on the server. Your audit logs will need to be in the following format:
# 
# > **%h %{ezproxy-session}i %u %t "%r" %s %b**
# 
# Please also maked sure that you place the EzProxy log files in the /data_e folder and that they are named in the syntax of "ezproxyYYYYMMDD.log" (for example, "ezproxy20190101.log"). These ezproxy files are usually in the /log sub-folder of your EzProxy application folder on the server. Your EzProxy logs will need to be in the following format, which is slightly different from the audit log format:
# 
# > **%h %{ezproxy-session}i %U %u %t "%r" %s %b**
# 
# Once you have some files in the approprate data folders, *run cells 1 through to 8*. If there are no warnings or errors, then you will be presented with a calendar dropdown menu, from which you can select the date for audting. Once you select a date, it will read the audit log for failed connections and then refresh with a 'username' dropdown, which presents users with the number of failed sessions they have held on the day in question. From this, you can select a user to see their location.
# 
# Once you select a username, the program will take a little moment to visualise where the user attempted to log into EzProxy. In normal circumstances,  under ten failed sessions and from the same location is usually normal behaviour for someone who is struggling to input their password correctly. A high number of failed sessions, sometimes coupled with multiple locations, can be a flag for suspicious behaviour.

# # Activate all cells

# In[1]:


import os
get_ipython().system('jupyter nbconvert --to script ezproxy_fails_daily.ipynb')
os.rename("./ezproxy_fails_daily.py", "./py/ezproxy_fails_daily.py")


# In[2]:


# FRESH ANACONDA INSTALL
# export PATH=/anaconda3/bin:$PATH
# conda config --add channels conda-forge
# conda install -c conda-forge proj4
# conda install -c anaconda mysql-connector-python
# conda install -c conda-forge cartopy
# conda install -c conda-forge tldextract
# conda install -c conda-forge basemap
# conda install -c conda-forge basemap-data-hires
# conda install -c conda-forge ipywidgets
# conda install -c conda-forge folium
# conda install -c conda-forge pyzmq
# conda install -c conda-forge jupyterlab
# conda install -c conda-forge nodejs
# conda install python=3.6.7
# jupyter nbextension enable --py widgetsnbextension
# jupyter labextension install @jupyter-widgets/jupyterlab-manager
# jupyter lab build


# In[3]:


import numpy as np
import pandas as pd
import random
import re
import sys
import matplotlib.pyplot as plt
import matplotlib
import mysql.connector
import matplotlib.dates as mdates
import cartopy.crs as ccrs
os.environ['PROJ_LIB'] = '/anaconda3/share/proj'
import requests
import json
import time
import csv
import tldextract
from datetime import datetime, timedelta, date
from ipywidgets import interact, interactive, interact_manual, Button, HBox, VBox, Layout, ButtonStyle
import ipywidgets as widgets
from IPython.display import display, clear_output, HTML
from mpl_toolkits.basemap import Basemap
import folium
from folium.plugins import MarkerCluster
pd.set_option('display.max_colwidth', -1)


# In[4]:


def on_date(change):
    global ddown
    global audit
    global thisDate2
    global sessDate
    global audits
    global audits_dict
    global thisDate
    today = date.today()
    today = int(today.strftime("%Y%m%d"))
    thisDate = aDates.value
    thisDate2 = str(aDates.value)
    thisDate3 = int(thisDate.strftime("%Y%m%d"))
    sessDate = thisDate.strftime("%Y%m%d")
    if thisDate3  > today:
        thisDate = date.today()
    thisDate = "./data/" + thisDate.strftime("%Y%m%d") + ".txt"
    audit = pd.read_csv(thisDate,sep='\t')
    audit = audit[audit.Event == "Login.Failure"]
    del audit['Date/Time']
    del audit['Other']
    del audit['Event']
    audit = audit[pd.notnull(audit['IP'])]
    audits = audit.groupby('Username').size()
    audits = pd.DataFrame({'Username':audits.index, 'Access':audits.values})
    audits = audits[audits.Access > 1]
    audits = audits.sort_values(by='Access',ascending=False)
    audits['Action'] = audits.Username.map(str)+" -- "+audits.Access.map(str)
    audits_dict = dict(zip(audits.Action,audits.Username,))
    with outB:
        clear_output()
        ddown = widgets.Dropdown(
            options = audits_dict,
            description = 'Usernames',
            disabled=False,
            value=None,
            rows=5
        )
        ddown.observe(on_user,names='value')
        display(ddown)
    with outC:
        clear_output()
        sessdown = widgets.Button(description="View World",layout=Layout(width="270px"))
        display(sessdown)
        sessdown.on_click(on_world)
    with outD:
        clear_output()
    with outG:
        clear_output()


# In[5]:


def on_world(b):
    global audit3
    global ipaudits
    global logX
    global ipr
    global ipc
    with outD:
        clear_output()
        ipr = []
        audit3 = pd.DataFrame(audit.groupby(['IP'], as_index=False)['IP'].agg(['count']))
        for row in audit3.index:
            ipr.append(row)
        ipr = list(set(ipr))
        thisFile = "./outputs/fail_world_" + thisDate2 + "_log.csv"
        with open(thisFile, mode='w') as audit_file:
            audit_writer = csv.writer(audit_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            audit_writer.writerow(["IP","lat","lon","city","dsize","continent_name",
                                   "threat_is_tor","threat_is_proxy",
                                   "threat_is_anonymous","threat_is_known_attacker",
                                   "threat_is_known_abuser","threat_is_threat","threat_is_bogon"])
            z = 0
            for x in ipr:
                url = "http://ip-api.com/json/" + x
                #apikey = ""
                #url = "https://api.ipdata.co/" + x + "?api-key=" + apikey
                r = requests.get(url)
                results = r.json()
                if len(results) > 1:
                    lat = results['lat']
                    lon = results['lon']
                    city = results['city']
                    #lat = results['latitude']
                    #lon = results['longitude']
                    #continent_name = results['continent_name']
                    #threat_is_tor = results['threat']['is_tor']
                    #threat_is_proxy = results['threat']['is_proxy']
                    #threat_is_anonymous = results['threat']['is_anonymous']
                    #threat_is_known_attacker = results['threat']['is_known_attacker']
                    #threat_is_known_abuser = results['threat']['is_known_abuser']
                    #threat_is_threat = results['threat']['is_threat']
                    #threat_is_bogon = results['threat']['is_bogon']
                    dsize = "10"
                    continent_name = ""
                    threat_is_tor = ""
                    threat_is_proxy = ""
                    threat_is_anonymous = ""
                    threat_is_known_attacker = ""
                    threat_is_known_abuser = ""
                    threat_is_threat = ""
                    threat_is_bogon = ""
                    audit_writer.writerow([x,lat,lon,city,dsize,continent_name,
                                           threat_is_tor,threat_is_proxy,threat_is_anonymous,
                                           threat_is_known_attacker,threat_is_known_abuser,
                                           threat_is_threat,threat_is_bogon])
                z = z + 1
                time.sleep(1.0)
                #time.sleep(0.2)                
        logs = pd.read_csv(thisFile)
        logZ = logs
        os.remove(thisFile)
        plt.figure(figsize=(17,17))
        ax = plt.axes(projection=ccrs.PlateCarree())
        ax.set_title('EzProxy Fails | World | ' + thisDate2,y=1.08)
        ax.set_global()
        ax.coastlines(linewidth=0.6)
        ax.stock_img()
        ax.gridlines(xlocs=range(-180,181,40), ylocs=range(-80,81,20),draw_labels=False)
        ax.gridlines(xlocs=range(-140,181,40), ylocs=range(-80,81,20),draw_labels=True)
        ax.text(-0.05,0,'Latitude', transform=ax.transAxes, rotation='vertical', va='bottom')
        ax.text(0,-0.07,'Longitude', transform=ax.transAxes, ha='left')
        for index, row in logZ.iterrows():
            lat = row['lat']
            lon = row['lon']
            latx = lat - 1.5
            lonx = lon + 3.5
            city = row['city']
            ds = row['dsize']
            ax.plot(lon, lat, marker='o', markersize=10, markerfacecolor='#FF0000')
        #plt.savefig('./imgs/ezproxy_fails_world_'+thisDate2+'_log.png', bbox_inches = "tight")
        plt.show();


# In[6]:


global aDates
now = datetime.utcnow() - timedelta(days=1)
aDates = widgets.DatePicker(
    description='Audit Date',
    disabled=False,
    value=datetime(now.year,now.month,now.day)
)
aDates.observe(on_date,names='value')


# In[7]:


def on_user(change):
    global sessdown
    global sessions
    global ipaddresses
    global ips
    global users
    global audit2
    global dataZ2
    global logZ
    with outG:
        clear_output()
        thisUser = ddown.value
        audit2 = audit[audit.Username == thisUser]
        user = []
        ipaddresses = []
        sessions = []
        for index, row in audit2.iterrows():
            if row['IP'] != "":
                aa = row['IP']
                bb = row['Username']
                cc = row['Session']
                ipaddresses.append(aa)
                user.append(bb)
                sessions.append(cc)
        ips = ipaddresses 
        ips = list(set(ips))
        users = [x for x in user if not pd.isnull(x)]
        users = list(set(users))
        thisFile = "./outputs/fail_" + users[0] + "_" + thisDate2 + "_log.csv"
        with open(thisFile, mode='w') as audit_file:
            audit_writer = csv.writer(audit_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            audit_writer.writerow(["IP","lat","lon","city","dsize","continent_name",
                                   "threat_is_tor","threat_is_proxy",
                                   "threat_is_anonymous","threat_is_known_attacker",
                                   "threat_is_known_abuser","threat_is_threat","threat_is_bogon"])
            z = 0
            for x in ips:
                url = "http://ip-api.com/json/" + x
                #apikey = ""
                #url = "https://api.ipdata.co/" + x + "?api-key=" + apikey
                r = requests.get(url)
                results = r.json()
                if len(results) > 1:
                    lat = results['lat']
                    lon = results['lon']
                    city = results['city']
                    #lat = results['latitude']
                    #lon = results['longitude']
                    #continent_name = results['continent_name']
                    #threat_is_tor = results['threat']['is_tor']
                    #threat_is_proxy = results['threat']['is_proxy']
                    #threat_is_anonymous = results['threat']['is_anonymous']
                    #threat_is_known_attacker = results['threat']['is_known_attacker']
                    #threat_is_known_abuser = results['threat']['is_known_abuser']
                    #threat_is_threat = results['threat']['is_threat']
                    #threat_is_bogon = results['threat']['is_bogon']
                    dsize = ""
                    continent_name = ""
                    threat_is_tor = ""
                    threat_is_proxy = ""
                    threat_is_anonymous = ""
                    threat_is_known_attacker = ""
                    threat_is_known_abuser = ""
                    threat_is_threat = ""
                    threat_is_bogon = ""
                    audit_writer.writerow([x,lat,lon,city,dsize,continent_name,
                                           threat_is_tor,threat_is_proxy,threat_is_anonymous,
                                           threat_is_known_attacker,threat_is_known_abuser,
                                           threat_is_threat,threat_is_bogon])
                z = z + 1
                time.sleep(1.0)
                #time.sleep(0.2)               
        logs = pd.read_csv(thisFile)
        logZ = logs
        os.remove(thisFile) 
        c = logZ.shape[0]
        if c > 0:
            plt.figure(figsize=(18, 15))
            m = Basemap(projection="lcc", width=9E6, height=5E6, lat_0=logZ['lat'][0], lon_0=logZ['lon'][0])
            m.shadedrelief()
            lat = logZ['lat']
            lon = logZ['lon']
            for i in range(0,len(lat)):
                x,y = m(lon[i],lat[i])
                m.plot(x, y, 'or', markersize=15, alpha=0.8)
            #plt.savefig('./imgs/ezproxy_fails_'+users[0]+'_'+thisDate2+'_log.png', bbox_inches = "tight")
            plt.show();
        else:
            print("Private IP Range")
            print(ips)


# In[8]:


outZ = widgets.Output(layout={'border': '0px solid #777777', 'height':'2.3em', 'padding': '0px', 'width':'99%'})
outA = widgets.Output(layout={'border': '0px solid #777777', 'height':'2.3em', 'padding': '0px', 'width':'310px'})
outB = widgets.Output(layout={'border': '0px solid #777777', 'height':'2.3em', 'padding': '0px', 'width':'310px'})
outC = widgets.Output(layout={'border': '0px solid #777777', 'height':'2.3em', 'padding': '0px', 'width':'310px', 'left': '30px'})
outD = widgets.Output(layout={'border': '0px solid #777777', 'height':'1200px', 'padding': '0px', 'width':'99%', 'top':'25px'})
outG = widgets.Output(layout={'border': '0px solid #777777', 'height':'600px', 'padding': '0px', 'width':'99%', 'top':'25px'})
interface = HBox([outA,outB,outC])
display(outZ)
display(interface)
display(outG)
display(outD)
with outA:
    clear_output()
    display(aDates)


# In[ ]:




