#!/usr/bin/env python
# coding: utf-8

# # EzProxy Daily : Users : Successful Logins

# ***This runs best in Jupyter, either on a local machine or on a server you have file access to.*** 
# 
# To review users accessing EzProxy and whether they are chaining multiple sessions, make sure you place the audit logs into the /data folder and that they are named in the syntax of "YYYYMMDD.txt" (for example, "20190314.txt"). These audit files are usually in the /audit sub-folder of your EzProxy application folder on the server. Your audit logs will need to be in the following format:
# 
# > **%h %{ezproxy-session}i %u %t "%r" %s %b**
# 
# Please also maked sure that you place the EzProxy log files in the /data_e folder and that they are named in the syntax of "ezproxyYYYYMMDD.log" (for example, "ezproxy20190101.log"). These ezproxy files are usually in the /log sub-folder of your EzProxy application folder on the server. Your EzProxy logs will need to be in the following format, which is slightly different from the audit log format:
# 
# > **%h %{ezproxy-session}i %U %u %t "%r" %s %b**
# 
# Once you have some files in the approprate data folders, *run cells 1 through to 8*. If there are no warnings or errors, then you will be presented with a calendar dropdown menu, from which you can select the date for audting. Once you select a date, it will read the audit log and then refresh with a 'username' dropdown, which presents users with the number of sessions they have held on the day in question. From this, you can select a user to review their activity based on the number of sessions they have generated. Usual bahaviour rarely goes into double digits; suspicious behaviour is always into double digits and often stands out from the rest of the list. In the image below, there are two users which warranted a review: one was legitimate (left side), the other was not legitimate and the user had to be contacted after their username was blocked (right side)
# 
# ![User Behaviour: Good on left, Bad on right](./docs/user_behaviour_reduced.jpg)
# 
# Once you select a username, the program will take a little moment to visualise where the user logged into EzProxy and where the user operated from after their logging in session was authenticated by EzProxy. In normal circumstances, both locations will match but in suspicious circumstances you may find that there are differences in locations or one location for logging in and multiple locations for general use. The latter scenario is usually indicative of the session being proxied out to other users (which sites like 'pubmed007' often do). You can verify this by clicking on the 'View Activity' button. This will generate a high-level list of resources accessed and other sites appearing in the logs. It is in the 'Other Sites' list where you will see any sites like 'pubmed007' or '2447.net'.

# # Activate all cells

# In[18]:


import os
get_ipython().system('jupyter nbconvert --to script ezproxy_daily_users.ipynb')
os.rename("./ezproxy_daily_users.py", "./py/ezproxy_daily_users.py")


# In[11]:


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


# In[12]:


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
pd.set_option('display.max_colwidth', -1)


# In[13]:


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
    audit["is_duplicate"] = audit.duplicated(['Username'])
    audit = audit[audit.Event == "Login.Success"]
    audit = audit[audit.is_duplicate == True]
    del audit['Date/Time']
    del audit['Other']
    del audit['Event']
    audit = audit[pd.notnull(audit['IP'])]
    audits = audit.groupby('Username').size()
    audits = pd.DataFrame({'Username':audits.index, 'Access':audits.values})
    audits = audits[audits.Access > 1]
    audits = audits.sort_values(by='Access',ascending=False)
    #audits = audits.sort_values(by='Username',ascending=False)
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
    with outD:
        clear_output()
    with outE:
        clear_output()
    with outF:
        clear_output()
    with outG:
        clear_output()


# In[14]:


global aDates
now = datetime.utcnow() - timedelta(days=1)
aDates = widgets.DatePicker(
    description='Audit Date',
    disabled=False,
#    value=datetime(now.year,now.month,now.day)
)
aDates.observe(on_date,names='value')


# In[15]:


def on_user(change):
    global sessdown
    global sessions
    global ipaddresses
    global ips
    global users
    global audit2
    global dataZ2
    global logZ
    with outC:
        clear_output()
    with outF:
        clear_output()
    with outE:
        clear_output()
    with outD:
        clear_output()
    with outG:
        clear_output()
    #Audit data
    thisUser = ddown.value
    audit2 = audit[audit.Username == thisUser]
    user = []
    ipaddresses = []
    sessions = []
    #Log data
    dataZ = pd.read_csv("./data_e/ezproxy" + sessDate + ".log", sep=" ", header=None, error_bad_lines=False, warn_bad_lines=False)
    dataZ.columns = ["ipaddress", "sessionid", "url", "urlsessionid", "adate", "azone", "adomain", "astatus", "asize"]
    dataZ2 = pd.DataFrame(dataZ)
    dataZ2 = dataZ2[dataZ2.urlsessionid == thisUser]
    dataZ3 = dataZ2.groupby(['ipaddress'], as_index=False)['ipaddress'].agg(['count'])
    ips2 = dataZ3.index.tolist()
    ips2 = list(set(ips2))
    for index, row in audit2.iterrows():
        if row['IP'] != "" and row['is_duplicate'] is True:
            aa = row['IP']
            bb = row['Username']
            cc = row['Session']
            ipaddresses.append(aa)
            user.append(bb)
            sessions.append(cc)
    ips = [x for x in ipaddresses if not pd.isnull(x)] 
    ips = list(set(ips))
    #ips2 = [x for x in ips2 if x not in ips]
    users = [x for x in user if not pd.isnull(x)]
    users = list(set(users))
    thisFile = "./outputs/" + users[0] + "_" + thisDate2 + "_log.csv"
    exists = os.path.isfile(thisFile)
    if exists:
        myLog = "Audit log CSV exists"
    else:
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
            for x in ips2:
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
        myLog = "Audit log CSV created"
    logs = pd.read_csv(thisFile)
    logZ = logs
    os.remove(thisFile)
    # Projection one
    plt.figure(figsize=(18, 15))
    m = Basemap(projection="lcc", width=9E6, height=5E6, lat_0=logZ['lat'][0], lon_0=logZ['lon'][0])
    m.shadedrelief()
    lat = logZ['lat']
    lon = logZ['lon']
    for i in range(0,len(lat)-1):
        x,y = m(lon[i],lat[i])
        m.plot(x, y, 'or', markersize=15, alpha=0.4)
    #plt.savefig('./imgs/ezproxy_intrusion_'+users[0]+'_'+thisDate2+'_log.png', bbox_inches = "tight")
    with outD:
        clear_output()
        plt.show();
    # Projection two
    plt.figure(figsize=(17,17))
    ax = plt.axes(projection=ccrs.PlateCarree())
    ax.set_title('EzProxy User | ' + users[0] + ' | ' + thisDate2,y=1.08)
    ax.set_global()
    ax.coastlines(linewidth=0.6)
    ax.stock_img()
    ax.gridlines(xlocs=range(-180,181,40), ylocs=range(-80,81,20),draw_labels=False)
    ax.gridlines(xlocs=range(-140,181,40), ylocs=range(-80,81,20),draw_labels=True)
    ax.text(-0.05,0,'Latitude', transform=ax.transAxes, rotation='vertical', va='bottom')
    ax.text(0,-0.07,'Longitude', transform=ax.transAxes, ha='left')
    for index, row in logs.iterrows():
        lat = row['lat']
        lon = row['lon']
        latx = lat - 1.5
        lonx = lon + 3.5
        city = row['city']
        ds = row['dsize']
        if ds != "L":
            ax.plot(lon, lat, marker='o', markersize=10, markerfacecolor='#FF0000')
        else:
            msg = "Do not plot"
        #ax.text(lonx, latx, city, fontsize=12, color='black')
    #plt.savefig('./imgs/ezproxy_intrusion_'+users[0]+'_'+thisDate2+'_audit.png', bbox_inches = "tight")
    with outC:
        clear_output()
        sessdown = widgets.Button(description="View Activity",layout=Layout(width="270px"))
        display(sessdown)
        sessdown.on_click(on_platform)
    with outF:
        clear_output()
    with outE:
        clear_output()
    with outG:
        clear_output()
        plt.show();


# In[16]:


def on_platform(b):
    global errorsA
    global errorsB
    global errorsC
    global data3
    errorsA = []
    errorsB = []
    errorsC = []
    thisUser = ddown.value
    with outE:
        clear_output()
        print("\t" + str(sessDate) + " / " + thisUser + " : This may take a minute ...",end="\n\n")
    with outF:
        clear_output()
    try:
        with outE:
            print("\tLoading log ...",end="\n\n")
        data = pd.read_csv("./data_e/ezproxy" + sessDate + ".log", sep=" ", header=None, error_bad_lines=False, warn_bad_lines=False)
        data.columns = ["ipaddress", "sessionid", "url", "urlsessionid", "adate", "azone", "adomain", "astatus", "asize"]
        #data2 = data
        data2 = pd.DataFrame(data[data["sessionid"].isin(sessions)])
        data2.reset_index(drop=True, inplace=True)
        with outE:
            print("\tParsing sessions ...",end="\n\n")
        data3 = {"ipaddress":[], "sessionid":[], "url":[], "time":[], "size":[]}
    except ValueError as e:
        errorsA.append("Catch 1 E: " + str(e))
    except IOError as e:
        errorsA.append("Catch 1a E: " + str(e))
    except:
        errorsA.append("Catch 1b E: ", sys.exc_info()[0])
    try:
        with outE:
            print("\tIterate over rows ...",end="\n\n")
        for i in data2.index:
            adate = data2.get_value(i,'adate')
            asize = data2.get_value(i,'asize')
            sessionid = data2.get_value(i,'sessionid')
            ipaddress = data2.get_value(i,'ipaddress')
            domain = data2.get_value(i,'url')
            matches = re.search("login", domain)
            matchesb = re.search("http[s]?://ezproxy.uws.edu.au", domain)
            adatex, datex = re.split("\[", adate)
            datex = pd.to_datetime(datex, format="%d/%b/%Y:%H:%M:%S")
            datex = datex.strftime('%H:%M')
            if domain is not None and domain != "" and domain != "-" and matches is None and matchesb is None:
                try:
                    dom, domy = re.split(".ezproxy.uws.edu.au", domain)
                except ValueError as e:
                    domain = re.sub("\-",".",str(domain))
                    extracted = tldextract.extract(domain)
                    domain = extracted.domain
                    errorsB.append(str(domain))
                    dom = None
                except IOError as e:
                    errorsB.append("Catch 2 E: " + str(e))
                    dom = None
                except:
                    errorsB.append("Catch 2a E: ", sys.exc_info()[0])
                    dom = None
            else:
                if domain is not None and domain != "" and domain != "-":
                    domain = re.sub("\-",".",str(domain))
                    extracted = tldextract.extract(domain)
                    domain = extracted.domain
                    errorsB.append(str(domain))
                dom = None
            try:
                if str(sessionid) != "-" and str(sessionid) != "" and str(dom) != "" and str(dom) != "None":
                    dom = re.sub("\-",".",str(dom))
                    extracted = tldextract.extract(dom)
                    dom = extracted.domain
                    data3["ipaddress"].append(str(ipaddress))
                    data3["sessionid"].append(str(sessionid))
                    data3["url"].append(str(dom))
                    data3["time"].append(datex)
                    data3["size"].append(asize)
                else:
                    if matches is not None or matchesb is not None:
                        errorsB.append("ezproxy")
                    else:
                        domain = re.sub("\-",".",str(data2.get_value(i,'url')))
                        extracted = tldextract.extract(domain)
                        domain = extracted.domain
                        errorsB.append(str(domain))
            except ValueError as v:
                errorsB.append("Catch 2b E: " + str(v))
            except IOError as v:
                errorsB.append("Catch 2c E: " + str(v))
            except:
                errorsB.append("Catch 2d E: sess " + str(type(sessionid)) + " dom " + str(type(dom)) + " error " + str(sys.exc_info()[0]))
    except ValueError as z:
        errorsC.append("Catch 3 E: " + str(z))
    except IOError as z:
        errorsC.append("Catch 3b E: " + str(z))
    except:
        errorsC.append("Catch 3c E: ", sys.exc_info()[0])
    with outE:
        print("\n\n\tGrouping and counting results",end="\n\n")
    try:
        df = pd.DataFrame(data3)
        df2 = df[df.sessionid.isin(sessions)]
        df3 = df2.groupby(['url'], as_index=False)['size'].agg(['sum','count'])
    except ValueError as e:
        errorsC.append("Catch 3d E: " + str(e))
    except IOError as e:
        errorsC.append("Catch 3e E: " + str(e))
    except:
        errorsC.append("Catch 3f E: ", sys.exc_info()[0])
    with outE:
        clear_output()
        display(HTML('<h4>Vendor Resources</h4>'))
        display(df3)
    dfObj = pd.DataFrame(errorsB, columns = ['url'])
    dfObj2 = dfObj.groupby(['url'], as_index=False)['url'].agg(['count'])
    dfObj2.drop(dfObj2[dfObj2['count'] < 2].index, inplace=True)
    dfObj2 = dfObj2.sort_values('count',ascending=False)
    with pd.option_context('display.max_rows', None, 'display.max_columns', None):
        with outF:
            clear_output()
            display(HTML('<h4>Other Sites<br />&nbsp;</h4>'))
            display(dfObj2)
            try:
                if max(data3["time"]) != "":
                    display(HTML('<h4>Most Recent Access<br />&nbsp;</h4>'))
                    display(max(data3["time"]))
                else:
                    display(HTML('<h4>No Recent Access<br />&nbsp;</h4>'))
            except:
                myError = "An error"


# In[17]:


outZ = widgets.Output(layout={'border': '0px solid #777777', 'height':'2.3em', 'padding': '0px', 'width':'99%'})
outA = widgets.Output(layout={'border': '0px solid #777777', 'height':'2.3em', 'padding': '0px', 'width':'310px'})
outB = widgets.Output(layout={'border': '0px solid #777777', 'height':'2.3em', 'padding': '0px', 'width':'310px'})
outC = widgets.Output(layout={'border': '0px solid #777777', 'height':'2.3em', 'padding': '0px', 'width':'310px', 'left': '30px'})
outD = widgets.Output(layout={'border': '0px solid #777777', 'height':'600px', 'padding': '0px', 'width':'99%', 'top':'25px'})
outG = widgets.Output(layout={'border': '0px solid #777777', 'height':'600px', 'padding': '0px', 'width':'99%', 'top':'25px'})
outE = widgets.Output(layout={'border': '0px solid #777777', 'height':'500px', 'padding': '0px', 'width':'495px', 'top':'35px', 'overflow_y':'auto', 'left': '30px'})
outF = widgets.Output(layout={'border-left': '1px solid #777777', 'height':'500px', 'padding': '0px', 'width':'495px', 'top':'35px', 'overflow_y':'auto'})
interface = HBox([outA,outB,outC])
interfaceb = HBox([outE,outF])
display(outZ)
display(interface)
display(outG)
display(outD)
display(interfaceb)
with outA:
    clear_output()
    display(aDates)


# In[ ]:




