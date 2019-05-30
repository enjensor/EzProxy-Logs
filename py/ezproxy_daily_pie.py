#!/usr/bin/env python
# coding: utf-8

# # EzProxy Daily : Pie

# ***This runs best in Jupyter, either on a local machine or on a server you have file access to.*** 
# 
# This script does a quick visualisation of the ratio of login types (failure, login, intruder, logout, and success) that your audit log has recorded. Make sure you place the audit logs into the /data folder and that they are named in the syntax of "YYYYMMDD.txt" (for example, "20190314.txt"). These audit files are usually in the /audit sub-folder of your EzProxy application folder on the server. Your audit logs will need to be in the following format:
# 
# > **%h %{ezproxy-session}i %u %t "%r" %s %b**
# 
# Once you have some files in the approprate data folders, *run cells 1 through to 7*. If there are no warnings or errors, then you will be presented with a calendar dropdown menu, from which you can select the date for audting. Once you select a date, a pie graph breaking down the types of activities found in your logs appears.

# # Activate all cells

# In[1]:


import os
get_ipython().system('jupyter nbconvert --to script ezproxy_daily_pie.ipynb')
os.rename("./ezproxy_daily_pie.py", "./py/ezproxy_daily_pie.py")


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


#now = datetime.utcnow() - timedelta(days=1)
#today = datetime(now.year,now.month,now.day)
#today = today.strftime("%Y%m%d")


# In[5]:


def on_date(change):
    global aDates
    global audits
    with outB:
        clear_output()
    utoday = aDates.value
    thisDate = "./data/" + utoday.strftime("%Y%m%d") + ".txt"
    audit = pd.read_csv(thisDate,sep='\t')
    audits = pd.DataFrame(audit.groupby('Event').count())
    del audits['Date/Time']
    del audits['IP']
    del audits['Session']
    del audits['Other']
    events = audits.index.tolist()
    values = audits.values.tolist()
    fig1, ax1 = plt.subplots()
    ax1.pie(values,startangle=90)
    centre_circle = plt.Circle((0,0),0.80,fc='white')
    fig = plt.gcf()
    fig.set_size_inches(7,7)
    fig.gca().add_artist(centre_circle)
    ax1.axis('equal') 
    plt.legend(events,loc=10)
    plt.tight_layout()
    #plt.savefig('./imgs/ezproxy_pie_'+today+'.png', bbox_inches = "tight")
    with outB:
        plt.show()


# In[6]:


global aDates
now = datetime.utcnow() - timedelta(days=1)
aDates = widgets.DatePicker(
    description='Audit Date',
    disabled=False,
#    value=datetime(now.year,now.month,now.day)
)
aDates.observe(on_date,names='value')


# In[7]:


outZ = widgets.Output(layout={'border': '0px solid #777777', 'height':'2.3em', 'padding': '0px', 'width':'99%'})
outA = widgets.Output(layout={'border': '0px solid #777777', 'height':'2.3em', 'padding': '0px', 'width':'310px'})
outB = widgets.Output(layout={'border': '0px solid #777777', 'height':'500px', 'padding': '0px', 'width':'495px', 'top':'35px', 'overflow_y':'auto', 'left': '30px'})
display(outZ)
display(outA)
display(outB)
with outA:
    clear_output()
    display(aDates)


# In[ ]:




