#!/usr/bin/env python
# coding: utf-8

# # Module 1: Data validation and pre-processing by each attack 

# In[1]:


#import library packages
import pandas as p
import numpy as n


# In[2]:


# feature names
features = ["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land", "Wrong_fragment", "Urgent", "hot", "num_failed_login", "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_ srv_rate", "dst_host_same_src_port_rate", "dst_host_srv_diff_host _rate", "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate","class"] 


# In[3]:


data = p.read_csv("data6.csv", names = features)
print(data.shape)


# In[4]:


data.dtypes


# Before drop the given dataset

# In[5]:


data.head(10)


# After drop the given dataset

# In[6]:


df=data.dropna()
df.shape


# In[7]:


df.head(10)


# In[8]:


#show columns
df.columns


# In[9]:


#To describe the dataframe
df.describe()


# In[10]:


#Checking datatype and information about dataset
df.info()


# Checking duplicate values of dataframe

# In[11]:


#Checking for duplicate data
df.duplicated()


# In[12]:


#find sum of duplicate data
sum(df.duplicated())


# In[13]:


#Checking sum of missing values
df.isnull().sum()


# In[14]:


d = p.crosstab(df['protocol_type'], df['class'])
d.plot(kind='bar', stacked=True, color=['red','green'], grid=False, figsize=(18,8))


# In[15]:


import matplotlib.pyplot as plt
pr = df["protocol_type"]
fl = df["flag"]
plt.plot(fl, pr, color='g')
plt.xlabel('Flag Types')
plt.ylabel('Protocol Types')
plt.title('Flag Details by protocol type')
plt.show()


# In[16]:


df["class"].unique()


# In[17]:


df['land'].value_counts()


# In[18]:


df['service'].value_counts()


# In[19]:


df['protocol_type'].value_counts()


# In[20]:


import numpy as n
def PropByVar(df, variable):
    dataframe_pie = df[variable].value_counts()
    ax = dataframe_pie.plot.pie(figsize=(10,10), autopct='%1.2f%%', fontsize = 12);
    ax.set_title(variable + ' (%) (Per Count)\n', fontsize = 15);
    return n.round(dataframe_pie/df.shape[0]*100,2)


PropByVar(df, 'protocol_type')


# In[21]:


df['DOSland'] = df.land.map({0:'attack',1:'noattack',2:'normal'})


# In[22]:


df['DOSlandclass'] = df.DOSland.map({'attack':1,'noattack':0,'normal':0})


# In[23]:


df['DOSlandclass'].value_counts()


# In[24]:


df['DOS'] = df['class'].map({'normal.':0, 'snmpgetattack.':0, 'named.':0, 'xlock.':0, 'smurf.':1,
       'ipsweep.':0, 'multihop.':0, 'xsnoop.':0, 'sendmail.':0, 'guess_passwd.':0,
       'saint.':0, 'buffer_overflow.':0, 'portsweep.':0, 'pod.':1, 'apache2.':1,
       'phf.':0, 'udpstorm.':1, 'warezmaster.':0, 'perl.':0, 'satan.':0, 'xterm.':0,
       'mscan.':0, 'processtable.':1, 'ps.':0, 'nmap.':0, 'rootkit.':0, 'neptune.':1,
       'loadmodule.':0, 'imap.':0, 'back.':1, 'httptunnel.':0, 'worm.':0,
       'mailbomb.':1, 'ftp_write.':0, 'teardrop.':1, 'land.':1, 'sqlattack.':0,
       'snmpguess.':0})


# In[25]:


df.head()


# In[26]:


df['R2L'] = df['class'].map({'normal.':0, 'snmpgetattack.':1, 'named.':1, 'xlock.':1, 'smurf.':0,
       'ipsweep.':0, 'multihop.':1, 'xsnoop.':1, 'sendmail.':1, 'guess_passwd.':1,
       'saint.':0, 'buffer_overflow.':0, 'portsweep.':0, 'pod.':0, 'apache2.':0,
       'phf.':1, 'udpstorm.':0, 'warezmaster.':1, 'perl.':0, 'satan.':0, 'xterm.':0,
       'mscan.':0, 'processtable.':0, 'ps.':0, 'nmap.':0, 'rootkit.':0, 'neptune.':0,
       'loadmodule.':0, 'imap.':1, 'back.':0, 'httptunnel.':1, 'worm.':1,
       'mailbomb.':0, 'ftp_write.':1, 'teardrop.':0, 'land.':0, 'sqlattack.':0,
       'snmpguess.':1})


# In[27]:


df['U2R'] = df['class'].map({'normal.':0, 'snmpgetattack.':0, 'named.':0, 'xlock.':0, 'smurf.':0,
       'ipsweep.':0, 'multihop.':0, 'xsnoop.':0, 'sendmail.':0, 'guess_passwd.':0,
       'saint.':0, 'buffer_overflow.':1, 'portsweep.':0, 'pod.':0, 'apache2.':0,
       'phf.':0, 'udpstorm.':0, 'warezmaster.':0, 'perl.':1, 'satan.':0, 'xterm.':1,
       'mscan.':0, 'processtable.':0, 'ps.':1, 'nmap.':0, 'rootkit.':1, 'neptune.':0,
       'loadmodule.':1, 'imap.':0, 'back.':0, 'httptunnel.':0, 'worm.':0,
       'mailbomb.':0, 'ftp_write.':0, 'teardrop.':0, 'land.':0, 'sqlattack.':1,
       'snmpguess.':0})


# In[28]:


df['Probe'] = df['class'].map({'normal.':0, 'snmpgetattack.':0, 'named.':0, 'xlock.':0, 'smurf.':0,
       'ipsweep.':1, 'multihop.':0, 'xsnoop.':0, 'sendmail.':0, 'guess_passwd.':0,
       'saint.':1, 'buffer_overflow.':0, 'portsweep.':1, 'pod.':0, 'apache2.':0,
       'phf.':0, 'udpstorm.':0, 'warezmaster.':0, 'perl.':0, 'satan.':1, 'xterm.':0,
       'mscan.':1, 'processtable.':0, 'ps.':0, 'nmap.':1, 'rootkit.':0, 'neptune.':0,
       'loadmodule.':0, 'imap.':0, 'back.':0, 'httptunnel.':0, 'worm.':0,
       'mailbomb.':0, 'ftp_write.':0, 'teardrop.':0, 'land.':0, 'sqlattack.':0,
       'snmpguess.':0})


# In[29]:


df['attack'] = df['class'].map({'normal.':0, 'snmpgetattack.':1, 'named.':1, 'xlock.':1, 'smurf.':1,
       'ipsweep.':1, 'multihop.':1, 'xsnoop.':1, 'sendmail.':1, 'guess_passwd.':1,
       'saint.':1, 'buffer_overflow.':1, 'portsweep.':1, 'pod.':1, 'apache2.':1,
       'phf.':1, 'udpstorm.':1, 'warezmaster.':1, 'perl.':1, 'satan.':1, 'xterm.':1,
       'mscan.':1, 'processtable.':1, 'ps.':1, 'nmap.':1, 'rootkit.':1, 'neptune.':1,
       'loadmodule.':1, 'imap.':1, 'back.':1, 'httptunnel.':1, 'worm.':1,
       'mailbomb.':1, 'ftp_write.':1, 'teardrop.':1, 'land.':1, 'sqlattack.':1,
       'snmpguess.':1})


# In[30]:


df.head()


# In[31]:


Corr=df.corr()
import matplotlib.pyplot as plt
plt.figure(figsize=(20, 10))
import seaborn as sns
sns.heatmap(data=Corr)



# Before Pre-Processing:

# In[32]:


df.head()
df.shape


# After Pre-Processing:

# In[33]:


df.columns


# In[34]:


from sklearn.preprocessing import LabelEncoder
var_mod = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes',
       'dst_bytes', 'land', 'Wrong_fragment', 'Urgent', 'hot',
       'num_failed_login', 'logged_in', 'num_compromised', 'root_shell',
       'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
       'num_access_files', 'num_outbound_cmds', 'is_host_login',
       'is_guest_login', 'count', 'srv_count', 'serror_rate',
       'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
       'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
       'dst_host_srv_count', 'dst_host_same_srv_rate',
       'dst_host_diff_ srv_rate', 'dst_host_same_src_port_rate',
       'dst_host_srv_diff_host _rate', 'dst_host_serror_rate',
       'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
       'dst_host_srv_rerror_rate', ]
le = LabelEncoder()
for i in var_mod:
    print(f'-------------------------------------------------->{df[i]}<-------------------------------')
    df[i] = le.fit_transform(df[i]).astype(str)
    print(df[i])


# In[35]:


df.head()


# In[36]:


df.dtypes


# In[ ]:




