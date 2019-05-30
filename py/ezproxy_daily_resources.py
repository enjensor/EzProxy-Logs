#!/usr/bin/env python
# coding: utf-8

# # EzProxy Daily : Resources

# ***This runs best in Jupyter, either on a local machine or on a server you have file access to.*** 
# 
# To review total use of EzProxy, make sure you place the audit logs into the /data folder and that they are named in the syntax of "YYYYMMDD.txt" (for example, "20190314.txt"). These audit files are usually in the /audit sub-folder of your EzProxy application folder on the server. Your audit logs will need to be in the following format:
# 
# > **%h %{ezproxy-session}i %u %t "%r" %s %b**
# 
# Please also maked sure that you place the EzProxy log files in the /data_e folder and that they are named in the syntax of "ezproxyYYYYMMDD.log" (for example, "ezproxy20190101.log"). These ezproxy files are usually in the /log sub-folder of your EzProxy application folder on the server. Your EzProxy logs will need to be in the following format, which is slightly different from the audit log format:
# 
# > **%h %{ezproxy-session}i %U %u %t "%r" %s %b**
# 
# Once you have some files in the approprate data folders, *run cells 1 through to 9*. If there are no warnings or errors, then you will be presented with a calendar dropdown menu, from which you can select the date for review. Once you select a date, it will read the logs and provide options for the following views. Keep in mind that because there will be thousands of IP addresses to query, it will take a very long time to obtain results. Best to run the script and come back to it an hour later.
# 
# ![Daily Resources: Birds' Eye View](./docs/daily_resources_reduced.png)

# # Activate all cells

# In[1]:


import os
get_ipython().system('jupyter nbconvert --to script ezproxy_daily_resources.ipynb')
os.rename("./ezproxy_daily_resources.py", "./py/ezproxy_daily_resources.py")


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
    global sessDate
    global sessdown
    global appsdown
    global errorsA
    global errorsB
    global errorsC
    global df
    global df5
    global df6
    global pf
    global data2
    global thisDate3
    global today
    errorsA = []
    errorsB = []
    errorsC = []
    today = date.today()
    today = int(today.strftime("%Y%m%d"))
    thisDate = aDates.value
    thisDate2 = str(aDates.value)
    thisDate3 = int(thisDate.strftime("%Y%m%d"))
    sessDate = thisDate.strftime("%Y%m%d")
    if thisDate3  > today:
        thisDate = date.today()
    with outB:
        clear_output()
    with outC:
        clear_output()
    with outCa:
        clear_output()
    with outD:
        clear_output()
        print("\t" + str(sessDate) + " : This may take a few minutes ...",end="\n\n")
    with outE:
        clear_output()
    with outG:
        clear_output()
    with outH:
        clear_output()
    with outJ:
        clear_output()
    with outK:
        clear_output()
    try:
        with outD:
            print("\tLoading log ...",end="\n\n")
        data = pd.read_csv("./data_e/ezproxy" + sessDate + ".log", sep=" ", header=None, error_bad_lines=False, warn_bad_lines=False)
        data.columns = ["ipaddress", "sessionid", "url", "urlsessionid", "adate", "azone", "adomain", "astatus", "asize"]
        data2 = pd.DataFrame(data)
        data2.reset_index(drop=True, inplace=True)
        with outD:
            print("\tParsing sessions ...",end="\n\n")
        data3 = {"ipaddress":[], "sessionid":[], "url":[], "time":[], "size":[]}
    except ValueError as e:
        errorsA.append("Catch 1 E: " + str(e))
    except IOError as e:
        errorsA.append("Catch 1a E: " + str(e))
    except:
        errorsA.append("Catch 1b E: ", sys.exc_info()[0])     
    with outD:
        print("\tIterate over rows ...",end="\n\n")
    try:
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
    with outD:
        print("\n\n\tGrouping and counting results",end="\n\n")
    try:
        df = pd.DataFrame(data3)
        df3 = df.groupby(['url'], as_index=False)['size'].agg(['sum','count'])
        df4 = df.groupby(['url'], as_index=False)['size'].agg(['count'])
        df5 = df.groupby(['ipaddress'], as_index=False)['size'].agg(['count','sum'])
        df6 = df4[df4["count"] > 250]
    except ValueError as e:
        errorsC.append("Catch 3d E: " + str(e))
    except IOError as e:
        errorsC.append("Catch 3e E: " + str(e))
    except:
        errorsC.append("Catch 3f E: ", sys.exc_info()[0])
    dfObj = pd.DataFrame(errorsB, columns = ['url'])
    dfObj2 = dfObj.groupby(['url'], as_index=False)['url'].agg(['count'])
    dfObj2.drop(dfObj2[dfObj2['count'] < 2].index, inplace=True)
    dfObj2 = dfObj2.sort_values('count',ascending=False)
#    with pd.option_context('display.max_rows', None, 'display.max_columns', None):
#        with outF:
#            clear_output()
#            display(HTML('<h4>Other Sites</h4>'))
#            display(dfObj2)
    with outD:
        clear_output()
        fig, ax = plt.subplots(figsize=(15,7))
        ax.set_title('EzProxy Resource Access | '+sessDate,y=1.08)
        fig.tight_layout()
        pff = df4.index.tolist()
        pf = df6.index.tolist()
        pv = []
        for sublist in df4.values:
            for item in sublist:
                pv.append(item)
        plt.ylim([0,45000])
        plt.xticks(fontsize=9, rotation=90)
        plt.bar(pff,pv)
        plt.savefig('./imgs/ezproxy_resources_'+sessDate+'.png', bbox_inches = "tight")
        plt.show()
    with outB:
        clear_output()
        sessdown = widgets.Button(description="View Locations",layout=Layout(width="240px"))
        display(sessdown)
        sessdown.on_click(on_world)
    with outC:
        clear_output()
        appsdown = widgets.Button(description="View Hourly Use",layout=Layout(width="240px"))
        display(appsdown)
        appsdown.on_click(on_hours)
    with outCa:
        clear_output()
        appsdown = widgets.Button(description="View Hourly Load",layout=Layout(width="240px"))
        display(appsdown)
        appsdown.on_click(on_stacked)


# In[5]:


def on_hours(b):
    global publishers
    global raw_data_list
    global raw_data
    global colors
    global i_values
    global a_values
    global downloads
    hours = ['00','01','02','03','04','05','06','07','08','09','10','11','12',
         '13','14','15','16','17','18','19','20','21','22','23']
    raw_data = pd.DataFrame(columns=['platform','platformValue'])
    raw_data_list = []
    publishers = pf
    for p in publishers:
        p_values = []
        for h in hours:
            dpp = df
            aa = dpp[(dpp["url"] == p) & (dpp["time"].str.contains(h+":\d\d",regex=True))].count()
            aa = aa["url"]
            p_values.append(aa)
        raw_data2 = raw_data.append({'platform':p,'platformValue':p_values}, ignore_index=True)
        raw_data = raw_data2
        raw_data_list.append(p_values)
    c = dict()
    r = lambda: random.randint(0,255)
    for i in range(0, len(publishers)+1):
        d = ('#%02X%02X%02X' % (r(),r(),r()))
        c[i] = d
    colors = c
    with outG:
        clear_output()
        matplotlib.rc('font', serif='Helvetica Neue')
        matplotlib.rcParams.update({'font.size': 10})
        fig = plt.gcf()
        fig, ax = plt.subplots(figsize=(18,20));
        N = len(hours)
        ind = np.arange(N)
        width = 0.75
        pi = []
        for i in range(0,len(publishers)):
            h = i-1
            t = publishers[i]
            if(i == 0):
                h = 0
                plt.bar(ind, raw_data_list[i], width, color=c[i])
            else:
                plt.bar(ind, raw_data_list[i], width, bottom=raw_data_list[h], color=c[i])
        plt.yticks(fontsize=12)
        plt.ylim([0,11000])
        plt.xticks(ind, hours, fontsize=12, rotation=45)
        ax.set_title('EzProxy Resource Use | '+sessDate,y=1.08)
        leg = plt.legend(publishers, fontsize=12, ncol=2, framealpha=0, fancybox=True, loc='upper left')
        legc = leg.legendHandles
        for i in range(0,len(publishers)):
            legc[i].set_color(c[i])
        plt.savefig('./imgs/ezproxy_resources_use'+sessDate+'.png', bbox_inches = "tight")
        plt.show();


# In[6]:


def on_world(b):
    global logs
    global logs2
    global data
    ips = df5.index.tolist()
    thisFile = "./outputs/resources_" + sessDate + "_log.csv"
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
                dsize = df5.iloc[z]["sum"]
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
            time.sleep(0.8)
            #time.sleep(0.2) 
    logs = pd.read_csv(thisFile)
    del logs['IP']
    del logs['threat_is_tor']
    del logs['threat_is_proxy']
    del logs['threat_is_anonymous']
    del logs['threat_is_known_attacker']
    del logs['threat_is_known_abuser']
    del logs['threat_is_threat']
    del logs['threat_is_bogon']
    logs2 = logs
    logs3 = logs
    logs = logs.groupby(['lat','lon','city','continent_name'], as_index=False)['city'].agg(['count'])
    plt.figure(figsize=(18,18))
    ax = plt.axes(projection=ccrs.PlateCarree())
    ax.set_title('EzProxy International Access | ' + sessDate,y=1.08)
    ax.set_global()
    ax.coastlines(linewidth=0.6)
    ax.stock_img()
    ax.gridlines(xlocs=range(-180,181,40), ylocs=range(-80,81,20),draw_labels=False)
    ax.gridlines(xlocs=range(-140,181,40), ylocs=range(-80,81,20),draw_labels=True)
    ax.text(-0.05,0,'Latitude', transform=ax.transAxes, rotation='vertical', va='bottom')
    ax.text(0,-0.07,'Longitude', transform=ax.transAxes, ha='left')
    i = 0
    imax = max(logs.values)
    for row in logs.index:
        lat = row[0]
        lon = row[1]
        latx = lat - 1.5
        lonx = lon + 3.5
        city = row[2]
        magnify = logs.iloc[i].values
        msize = int((100 / imax) * magnify)
        if msize < 10:
            msize = 10
        if msize > 50:
            msize = 50
        i = i + 1
        ax.plot(lon, lat, marker="o", markersize=10, markerfacecolor=(1,0,0,1.0),
                markeredgecolor=(1,0,0,1.0),markeredgewidth=0.1,fillstyle="full")
    with outE:
        clear_output()
        plt.savefig('./imgs/ezproxy_resource_access_'+sessDate+'.png', bbox_inches = "tight")
        plt.show();
    #data = logs2.groupby(['lat','lon','city','continent_name'], as_index=False)['dsize'].agg(['count'])
    data = logs2.groupby(['lat','lon','city','continent_name'], as_index=False)['dsize'].agg(['sum'])
    data['labels_enc'] = pd.factorize(data.index.get_level_values('continent_name'))[0]
    plt.figure(figsize=(18,18))
    #m = Basemap(llcrnrlon = -180, llcrnrlat = -80, urcrnrlon = 180, urcrnrlat = 80)
    m = Basemap(lat_0=-31.840233, lon_0=146.9211)
    #m.drawmapboundary(fill_color = '#f9fafa', linewidth = 0)
    #m.fillcontinents(color = '#b1c8b0', alpha = 0.5)
    m.shadedrelief()
    #m.drawcoastlines(linewidth = 0.0, color = "black")
    m.scatter(data.index.get_level_values('lon'), 
              data.index.get_level_values('lat'), 
              s = data.values/60000, alpha=0.5, 
              #s = data.values*20, alpha=0.5,
              c = data['labels_enc'], 
              cmap = "Set1")
    plt.title('EzProxy Resource Load Distribution | ' + sessDate,y=1.08)
    with outH:
        clear_output()
        plt.savefig('./imgs/ezproxy_distribution_'+sessDate+'.png', bbox_inches = "tight")
        plt.show();
    plt.figure(figsize=(18, 15))
    m = Basemap(projection="lcc", width=7E6, height=5E6, lat_0=-29, lon_0=141)
    m.shadedrelief()
    data = logs3.groupby(['lat','lon','city','continent_name'], as_index=False)['dsize'].agg(['count'])
    lat = data.index.get_level_values('lat')
    lon = data.index.get_level_values('lon')
    for i in range(0,len(lat)-1):
        x,y = m(lon[i],lat[i])
        m.plot(x, y, 'or', markersize=7, alpha=0.5)
    plt.title('EzProxy Australian Access | ' + sessDate,y=1.05)
    with outJ:
        clear_output()
        plt.savefig('./imgs/ezproxy_australia_'+sessDate+'.png', bbox_inches = "tight")
        plt.show();


# In[7]:


def on_stacked(b):
    global ti_values
    global ta_values
    global tdownloads
    with outK:
        hours = ['00','01','02','03','04','05','06','07','08','09','10','11','12','13','14','15','16','17','18','19','20','21','22','23']
        blacklist = pd.read_csv("./data_ips/blacklist.txt", sep=",", header=None, error_bad_lines=False, warn_bad_lines=False)
        blacklist.columns = ["IRN","IPAddress","OrganisationName","ReportedBy","ThreatType","IsWhiteListed","DateCreated","Notes"]
        blackips = blacklist["IPAddress"]
        data3 = pd.DataFrame(data2)
        data3.drop('azone', axis=1, inplace=True)
        data3.drop('url', axis=1, inplace=True)
        data3.drop('astatus', axis=1, inplace=True)
        data3.drop('sessionid', axis=1, inplace=True)
        data4 = data3["adate"].str.split(pat = ":", expand=True)
        data3["adate"] = data4.loc[:,1]
        data3["asize"] = round(data3["asize"] / 1024 / 1024)
        ips = data3.groupby(['ipaddress','adate'], as_index=True)['adate'].agg(['count']).index.tolist()
        counts = data3.groupby(['ipaddress','adate'], as_index=True)['adate'].agg(['count']).values.tolist()
        downloads = data3.groupby(['adate'], as_index=True)['asize'].sum().values.tolist()
        d = (24 - len(downloads))
        if d > 0:
            for q in range(0,d):
                qq = 0
                downloads.append(qq)
        df = pd.DataFrame(np.array(ips),columns=["ipaddress","dates"])
        df["counts"] = counts
        i_values = []
        a_values = []
        for h in hours: 
            ii = df[(df["dates"].str.contains(h,regex=True))].count()
            if ii["ipaddress"] != "" and ii["ipaddress"] is not None:
                ii = ii["ipaddress"]
            else:
                ii = 0       
            i_values.append(ii)
            aa = df[(df["dates"].str.contains(h,regex=True))].sum()
            if aa["counts"] != "" and aa["counts"] is not None:
                try:
                    aa = round(sum(aa["counts"])/100)
                except ValueError as e:
                    aa = 0
                except IOError as e:
                    aa = 0
                except:
                    aa = 0
            else:
                aa = round(0)
            a_values.append(aa)
        x = hours
        y = [i_values,a_values,downloads]
        ti_values = i_values
        ta_values = a_values
        tdownloads = downloads
        plt.figure(figsize=(18,10))
        plt.ylim([0,4000])
        plt.stackplot(x,y, labels=['Unique IPs','Unique Web Requests (x100)','Total Traffic (Mb)'])
        plt.legend(loc='upper left')
        plt.title('EzProxy Hourly Load | ' + sessDate,y=1.08)
        clear_output()
        plt.savefig('./imgs/ezproxy_daily_stacked_'+sessDate+'.png', bbox_inches = "tight")
        plt.show();


# In[8]:


global aDates
now = datetime.utcnow() - timedelta(days=1)
aDates = widgets.DatePicker(
    description='Log Date',
    disabled=False,
    value=datetime(now.year,now.month,now.day)
)
aDates.observe(on_date,names='value')


# In[9]:


outZ = widgets.Output(layout={'border': '0px solid #777777', 'height':'2.3em', 'padding': '0px', 'width':'99%'})
outA = widgets.Output(layout={'border': '0px solid #777777', 'height':'2.3em', 'padding': '0px', 'width':'310px'})
outB = widgets.Output(layout={'border': '0px solid #777777', 'height':'2.3em', 'padding': '0px', 'width':'250px'})
outC = widgets.Output(layout={'border': '0px solid #777777', 'height':'2.3em', 'padding': '0px', 'width':'250px'})
outCa = widgets.Output(layout={'border': '0px solid #777777', 'height':'2.3em', 'padding': '0px', 'width':'250px'})
outD = widgets.Output(layout={'border': '0px solid #777777', 'height':'650px', 'padding': '0px', 'width':'99%', 'top':'25px', 'overflow':'hidden'})
outE = widgets.Output(layout={'border': '0px solid #777777', 'height':'650px', 'padding': '0px', 'width':'99%', 'top':'25px', 'overflow':'hidden'})
outH = widgets.Output(layout={'border': '0px solid #777777', 'height':'650px', 'padding': '0px', 'width':'99%', 'top':'25px', 'overflow':'hidden', 'left':'43px'})
outJ = widgets.Output(layout={'border': '0px solid #777777', 'height':'800px', 'padding': '0px', 'width':'99%', 'top':'25px', 'overflow':'hidden', 'left':'43px'})
outG = widgets.Output(layout={'border': '0px solid #777777', 'height':'1330px', 'padding': '0px', 'width':'99%', 'top':'25px', 'overflow':'hidden'})
outF = widgets.Output(layout={'border': '0px solid #777777', 'height':'800px', 'padding': '0px', 'width':'99%', 'top':'35px', 'overflow':'hidden'})
outK = widgets.Output(layout={'border': '0px solid #777777', 'height':'650px', 'padding': '0px', 'width':'99%', 'top':'5px', 'overflow':'hidden'})
interface = HBox([outA,outB,outC,outCa])
interfaceb = HBox([outE,outF])
display(outZ)
display(interface)
display(outD)
display(outE)
display(outH)
display(outJ)
display(outG)
display(outK)
with outA:
    clear_output()
    display(aDates)


# In[ ]:


#import imageio
#import fnmatch
#import moviepy.editor as mp
#folders = ["ezproxy_australia","ezproxy_daily_stacked","ezproxy_distribution",
#           "ezproxy_resource_access","ezproxy_resources_2019","ezproxy_resources_use"]
#for f in folders:
#    print(f)
#    images = []
#    for file in sorted(os.listdir('./imgs')):
#        if fnmatch.fnmatch(file, f+'*'):
#            images.append(imageio.imread("./imgs/"+file))
#    imageio.mimsave('./mvs/'+f+'.gif', images, duration=0.10)
#    clip = mp.VideoFileClip("./mvs/"+f+".gif")
#    clip.write_videofile("./mvs/"+f+".mp4")
#print("done")

