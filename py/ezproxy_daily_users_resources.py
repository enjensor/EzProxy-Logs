#!/usr/bin/env python
# coding: utf-8

# # EzProxy Daily : Detailed Hourly View of Resource Use

# ***This runs best in Jupyter, either on a local machine or on a server you have file access to.*** 
# 
# ***You use this script when you want to review an hour in detail after seeing the hourly use and hourly load in the EzProxy Daily Resources routine***
# 
# To review total use of EzProxy, make sure you place the audit logs into the /data folder and that they are named in the syntax of "YYYYMMDD.txt" (for example, "20190314.txt"). These audit files are usually in the /audit sub-folder of your EzProxy application folder on the server. Your audit logs will need to be in the following format:
# 
# > **%h %{ezproxy-session}i %u %t "%r" %s %b**
# 
# Please also maked sure that you place the EzProxy log files in the /data_e folder and that they are named in the syntax of "ezproxyYYYYMMDD.log" (for example, "ezproxy20190101.log"). These ezproxy files are usually in the /log sub-folder of your EzProxy application folder on the server. Your EzProxy logs will need to be in the following format, which is slightly different from the audit log format:
# 
# > **%h %{ezproxy-session}i %U %u %t "%r" %s %b**
# 
# Once you have some files in the approprate data folders, *run all cells*. If there are no warnings or errors, then you will be presented with a calendar dropdown menu, from which you can select the date for review, and a dropdown list of 24 hours, from which you can select the hour for review. Once you select a date and hour, click the 'View' button to see the top 50 users in terms of web requests and downloads. A map will also show where the top user is accessing EzProxy from.

# # Activate all cells

# In[1]:


#Backup python script
import os
get_ipython().system('jupyter nbconvert --to script ezproxy_daily_users_resources.ipynb')
os.rename("./ezproxy_daily_users_resources.py", "./py/ezproxy_daily_users_resources.py")


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


#Python Modules
import numpy as np
import pandas as pd
import random
import re
import sys
import matplotlib.pyplot as plt
import matplotlib
import mysql.connector
import matplotlib.dates as mdates
import matplotlib.patches as mpatches
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
pd.set_option("display.max_rows", None)
import warnings; warnings.simplefilter('ignore')


# In[4]:


#Dates Widget
global aDates
now = datetime.utcnow() - timedelta(days=1)
aDates = widgets.DatePicker(
    description='Date',
    disabled=False,
    layout={'width': '260px'},
    value=datetime(now.year,now.month,now.day)
)


# In[5]:


#Hours Widget
global aHours
aHours = widgets.Dropdown(
    options=['00','01','02','03','04','05','06','07','08','09','10','11','12','13','14','15','16','17','18','19','20','21','22','23'],
    value='12',
    layout={'width': '150px'},
    description='Hour:',
    disabled=False,
)


# In[6]:


#Not Logged In Users Checkbox
global aLogins
aLogins = widgets.Checkbox(
    value=False,
    description='Include Unverified Users',
    disabled=False
)


# In[7]:


#Review users according to date and hour selected
def on_users(b):
    global aDates
    global aHours
    global data2
    global data3
    global data4
    global df1
    global df2
    global df3
    global df4
    global df6
    global df7
    global df8
    global df9
    global df10
    global tUser
    global tUrl
    global tIpaddress
    global results
    global ips
    hValues = []
    errorsA = []
    today = date.today()
    today = int(today.strftime("%Y%m%d"))
    thisDate = aDates.value
    thisDate2 = str(aDates.value)
    thisDate3 = int(thisDate.strftime("%Y%m%d"))
    sessDate = thisDate.strftime("%Y%m%d")
    if thisDate3  > today:
        thisDate = date.today()
    try:
        with outM:
            clear_output()
        with outK:
            clear_output()
        with outJ:
            clear_output()
        with outH:
            clear_output()
        with outG:
            clear_output()
        with outF:
            clear_output()
            print("\tLoading log ...",end="\n\n")
        data = pd.read_csv("./data_e/ezproxy" + sessDate + ".log", sep=" ", header=None, error_bad_lines=False, warn_bad_lines=False)
        data.columns = ["ipaddress", "sessionid", "url", "urlsessionid", "adate", "azone", "adomain", "astatus", "asize"]
        data2 = pd.DataFrame(data)
        data2.reset_index(drop=True, inplace=True)
        with outF:
            print("\tParsing sessions ...",end="\n\n")
    except ValueError as e:
        errorsA.append("Catch 1 E: " + str(e))
    except IOError as e:
        errorsA.append("Catch 2 E: " + str(e))
    except:
        errorsA.append("Catch 3 E: ", sys.exc_info()[0])     
    with outF:
        print("\tConstraining to chosen hour ...",end="\n\n")
    try:
        with outF:
            h = str(aHours.value) + ":"
            data3 = {"user":[], "ipaddress":[], "sessionid":[], "urltime":[], "url":[], "size":[]}
            for i in data2.index:
                user = data2.get_value(i,'urlsessionid')
                ipaddress = data2.get_value(i,'ipaddress')
                sessionid = data2.get_value(i,'sessionid')
                adate = data2.get_value(i,'adate')
                adatex, datex = re.split("\[", adate)
                datex = pd.to_datetime(datex, format="%d/%b/%Y:%H:%M:%S")
                urltime = datex.strftime('%H:%M')
                url = data2.get_value(i,'url')
                url = url.strip("GET ")
                url = url.strip("POST ")
                url = url.strip("IONS ")
                url = url.strip("HEAD ")
                url = re.sub("\-",".",str(url))
                url = re.sub(".ezproxy.uws.edu.au","",str(url))
                extracted = tldextract.extract(url)
                url = extracted.domain
                size = data2.get_value(i,'asize')
                data3["user"].append(str(user))
                data3["ipaddress"].append(str(ipaddress))
                data3["sessionid"].append(str(sessionid))
                data3["urltime"].append(str(urltime))
                data3["url"].append(str(url))
                data3["size"].append(str(size))
            clear_output()
            print("\tEvaluating data ...",end="\n\n")
            data4 = pd.DataFrame.from_dict(data3)
            data4 = data4[(data4["urltime"].str.contains(h,regex=True))]
    except ValueError as e:
        errorsA.append("Catch 4 E: " + str(e))
    except IOError as e:
        errorsA.append("Catch 5 E: " + str(e))
    except:
        errorsA.append("Catch 6 E: ", sys.exc_info()[0])
    try:
        with outF:
            clear_output()
            #Top 50 web requests
            df = pd.DataFrame(data4)
            #df.size = df.size.astype(int)
            df["size"] = df["size"].astype(dtype=np.int64)
            df1 = pd.DataFrame(df.groupby(['user'])['size'].agg(['sum','count']))
            if aLogins.value is False:
                df2 = df1[df1.index != "-"]
                df3 = df2[df2.index != "auto"]
            else:
                df2 = df1
                df3 = df1
            df3 = df3.sort_values('count',ascending=False)      
            df3 = df3.reset_index() 
            df3 = df3.drop(df3.index[50:])
            if aLogins.value is False:
                df0 = df2[df2.index != "auto"]
            else:
                df0 = df2
            me = df0['count'].tolist()
            yb = df3.iloc[0]['count']
            yb = int(5 * round(float(yb)/5))
            yb = yb + 5
            df3['user'].replace('-', 'UNVERIFIED', inplace=True)
            dc = df3['count'].tolist()
            du = df3['user'].tolist()
            ym = [np.mean(dc)]*len(du)
            yn = [np.mean(me)]*len(du)
            fig, ax = plt.subplots(figsize=(15,7))
            ax.set_title('EzProxy Web Requests : Hour '+aHours.value,y=1.04)
            fig.tight_layout()
            plt.ylim([0,yb])
            plt.xticks(fontsize=9, rotation=90)
            blist = plt.bar(du,dc,label='User Peak (http)',color='#CCCCCC')
            blist[0].set_color('r')
            mean_line = ax.plot(du,ym,label='Top 50 Users Average',linestyle='--',color='b')
            mean_line2 = ax.plot(du,yn,label='All Users Average',linestyle='--',color='g')
            plt.legend(fontsize=12, loc='upper right')
            plt.show()
        with outG:
            clear_output()
            #Top 50 downloads
            if aLogins.value is False:
                df4 = df2[df2.index != "auto"]
            else:
                df4 = df2
            df4 = df4.sort_values('sum',ascending=False)
            df4 = df4.reset_index()
            df4 = df4.drop(df4.index[50:])
            df4["sum"] = round(df4["sum"] / 1024 / 1024)
            if aLogins.value is False:
                df0 = df2[df2.index != "auto"]
            else:
                df0 = df2
            df0["sum"] = round(df0["sum"] / 1024 / 1024)
            me = df0['sum'].tolist()
            zb = df4.iloc[0]['sum']
            zb = int(5 * round(float(zb)/5))
            zb = zb + 5
            df4['user'].replace('-', 'UNVERIFIED', inplace=True)
            tUser = df4.iloc[0]['user']
            hc = df4['sum'].tolist()
            hu = df4['user'].tolist()
            hn = [np.mean(hc)]*len(hu)
            hm = [np.mean(me)]*len(hu)
            fig, ax = plt.subplots(figsize=(15,7))
            ax.set_title('EzProxy Download : Hour '+aHours.value,y=1.04)
            fig.tight_layout()
            plt.ylim([0,zb])
            plt.xticks(fontsize=9, rotation=90)
            blist = plt.bar(hu,hc,label='User Peak (mb)',color='#CCCCCC')
            blist[0].set_color('r')
            mean_line = ax.plot(hu,hn,label='Top 50 Users Average',linestyle='--',color='b')
            mean_line2 = ax.plot(hu,hm,label='All Users Average',linestyle='--',color='g')
            plt.legend(fontsize=12, loc='upper right')
            plt.show()
        with outH:
            clear_output()
            #Geolocate top user(s)
            lat = []
            lon = []
            city = []
            df6 = pd.DataFrame(data4)
            df6['user'].replace('-', 'UNVERIFIED', inplace=True)
            df6 = df6[df6.user == tUser]
            df6 = df6.groupby(['ipaddress'], as_index=False)['ipaddress'].agg(['count'])
            ips = df6.index.tolist()
            ips = list(set(ips))
            for x in ips:
                if x != "":
                    url = "http://ip-api.com/json/" + x
                    r = requests.get(url)
                    results = r.json()
                    if len(results) > 1:
                        if 'lat' in results:
                            lat.append(results['lat'])
                            lon.append(results['lon'])
                            city.append(results['city'])
                    time.sleep(1.0)
            if aLogins.value is False:
                plt.figure(figsize=(19, 15))
                m = Basemap(projection="lcc", width=9E6, height=5E6, lat_0=lat[0], lon_0=lon[0])
                m.shadedrelief()
                for i in range(0,len(lat)):
                    x,y = m(lon[i],lat[i])
                    m.plot(x, y, 'or', markersize=15, alpha=1.0)
                    plt.text(x, y, "   "+city[i], fontsize=11, color='black', ha='left', va='center')
                plt.title('Download Location(s) for User : '+tUser,y=1.04)
                plt.show();
            else:
                plt.figure(figsize=(17,17))
                ax = plt.axes(projection=ccrs.PlateCarree())
                ax.set_title('Download Location(s) for User : '+tUser,y=1.04)
                ax.set_global()
                ax.coastlines(linewidth=0.6)
                ax.stock_img()
                ax.gridlines(xlocs=range(-180,181,40), ylocs=range(-80,81,20),draw_labels=False)
                ax.gridlines(xlocs=range(-140,181,40), ylocs=range(-80,81,20),draw_labels=True)
                ax.text(-0.05,0,'Latitude', transform=ax.transAxes, rotation='vertical', va='bottom')
                ax.text(0,-0.07,'Longitude', transform=ax.transAxes, ha='left')
                for i in range(0,len(lat)):
                    ax.plot(lon[i], lat[i], marker='o', markersize=10, markerfacecolor='#FF0000')
                plt.show();
        with outJ:
            clear_output()
            #Resource Use
            df8 = pd.DataFrame(data4)
            df8 = df8.groupby(['url'], as_index=False)['size'].agg(['sum','count'])
            if aLogins.value is False:
                df8 = df8[df8.index != "auto"]
                df8 = df8[df8.index != ""]
            df8 = df8.sort_values('sum',ascending=False)      
            df8 = df8.reset_index()
            df8["sum"] = round(df8["sum"] / 1024 / 1024)
            df8 = df8.drop(df8.index[50:])
            df9 = pd.DataFrame(data4)
            df9 = df9[df9.user == tUser]
            df9 = df9.groupby(['url'], as_index=False)['size'].agg(['sum','count'])
            if aLogins.value is False:
                df9 = df9[df9.index != "auto"]
                df9 = df9[df9.index != ""]
            df9 = df9.sort_values('sum',ascending=False)      
            df9 = df9.reset_index()
            df9["sum"] = round(df9["sum"] / 1024 / 1024)
            df9 = df9.drop(df9.index[50:])
            tUrl = df9.iloc[0]['url']
            df8['url'].replace('', 'uws', inplace=True)
            df10 = pd.merge(left=df8,right=df9, how='left', left_on='url', right_on='url')
            df10 = df10.sort_values('url',ascending=True)
            df10.drop('count_x', axis=1, inplace=True)
            df10.drop('count_y', axis=1, inplace=True)
            df10['sum_y'].replace(np.NaN, 0.0, inplace=True)
            df10["sum_x"] = df10["sum_x"] - df10["sum_y"]
            fig, ax = plt.subplots(figsize=(15,7))
            ax.set_title('Resources Downloaded by User : '+tUser,y=1.04)
            fig.tight_layout()
            names = df10['url'].tolist()
            bars1 = df10['sum_x'].tolist()
            bars2 = df10['sum_y'].tolist()
            plt.bar(names, bars1, color='#cccccc', edgecolor='white', width=1)
            plt.bar(names, bars2, bottom=bars1, color='r', edgecolor='white', width=1)
            redPatch = mpatches.Patch(color='#ff0000', label='Peak User Resources Downloaded (mb)')
            grayPatch = mpatches.Patch(color='#cccccc', label='Other Users (mb)')
            plt.legend(handles=[redPatch,grayPatch], fontsize=12, loc='upper right')
            plt.xticks(fontsize=10, rotation=90)
            plt.show();
        with outK:
            df11 = pd.DataFrame(data4)
            df11 = df11[df11.user == "UNVERIFIED"]
            df11 = df11.groupby(['ipaddress'], as_index=False)['size'].agg(['sum','count'])
            df11 = df11.sort_values('count',ascending=False) 
            df11 = df11.reset_index()
            df11 = df11.head(50)
            fig, ax = plt.subplots(figsize=(15,7))
            ax.set_title('UNVERIFIED Access Attempts : Hour '+aHours.value,y=1.04)
            fig.tight_layout()
            plt.xticks(fontsize=9, rotation=90)
            blist = plt.bar(df11['ipaddress'],df11['count'],label='Unverified Users (http)',color='#CCCCCC')
            blist[0].set_color('r')
            tIpaddress = df11['ipaddress'][0]
            redPatch = mpatches.Patch(color='#ff0000', label='Peak Unverified User (http)')
            grayPatch = mpatches.Patch(color='#cccccc', label='Unverified Users (http)')
            plt.legend(handles=[redPatch,grayPatch], fontsize=12, loc='upper right')
            plt.show()
        with outM:
            lat = []
            lon = []
            city = []
            if x != "":
                url = "http://ip-api.com/json/" + tIpaddress
                r = requests.get(url)
                results = r.json()
                if len(results) > 1:
                    if 'lat' in results:
                        lat.append(results['lat'])
                        lon.append(results['lon'])
                        city.append(results['city'])
            if len(lon) > 0:
                plt.figure(figsize=(19, 15))
                m = Basemap(projection="lcc", width=9E6, height=5E6, lat_0=lat[0], lon_0=lon[0])
                m.shadedrelief()
                for i in range(0,len(lat)):
                    x,y = m(lon[i],lat[i])
                    m.plot(x, y, 'or', markersize=15, alpha=1.0)
                    plt.text(x, y, "   "+city[i], fontsize=11, color='black', ha='left', va='center')
                plt.title('Location for UNVERIFIED User at '+str(tIpaddress),y=1.04)
                plt.show();
    except ValueError as e:
        errorsA.append("Catch 7 E: " + str(e))
    except IOError as e:
        errorsA.append("Catch 8 E: " + str(e))
    except:
        errorsA.append("Catch 9 E: ", sys.exc_info()[0])


# In[8]:


#Layout
outZ = widgets.Output(layout={'border': '0px solid #777777', 'height':'2.3em', 'padding': '0px', 'width':'99%'})
outZa = widgets.Output(layout={'border': '0px solid #777777', 'height':'2.3em', 'padding': '0px', 'width':'99%'})
outA = widgets.Output(layout={'border': '0px solid #777777', 'height':'2.3em', 'padding': '0px', 'width':'270px'})
outB = widgets.Output(layout={'border': '0px solid #777777', 'height':'2.3em', 'padding': '0px', 'width':'160px'})
outC = widgets.Output(layout={'border': '0px solid #777777', 'height':'2.3em', 'padding': '0px', 'width':'180px'})
outD = widgets.Output(layout={'border': '0px solid #777777', 'height':'2.3em', 'padding': '0px', 'width':'330px'})
outF = widgets.Output(layout={'border': '0px solid #777777', 'height':'600px', 'padding': '0px', 'width':'99%', 'top':'25px', 'overflow_y':'auto'})
outG = widgets.Output(layout={'border': '0px solid #777777', 'height':'600px', 'padding': '0px', 'width':'99%', 'top':'25px'})
outH = widgets.Output(layout={'border': '0px solid #777777', 'height':'600px', 'padding': '0px', 'width':'99%', 'top':'25px'})
outJ = widgets.Output(layout={'border': '0px solid #777777', 'height':'600px', 'padding': '0px', 'width':'99%', 'top':'25px'})
outK = widgets.Output(layout={'border': '0px solid #777777', 'height':'600px', 'padding': '0px', 'width':'99%', 'top':'25px'})
outM = widgets.Output(layout={'border': '0px solid #777777', 'height':'600px', 'padding': '0px', 'width':'99%', 'top':'25px'})
interface = HBox([outC,outB,outA,outD])
display(outZ)
display(interface)
display(outF)
display(outG)
display(outH)
display(outJ)
display(outK)
display(outM)
display(outZa)
with outA:
    clear_output()
    display(aDates)
with outB:
    clear_output()
    display(aHours)
with outC:
    clear_output()
    sessdown = widgets.Button(description="View Use",layout=Layout(width="170px"))
    display(sessdown)
    sessdown.on_click(on_users)
with outD:
    clear_output()
    display(aLogins)


# In[ ]:




