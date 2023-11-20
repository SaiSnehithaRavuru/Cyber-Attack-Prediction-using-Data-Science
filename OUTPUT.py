#!/usr/bin/env python
# coding: utf-8

# In[1]:


#import library packages
import pandas as p
import matplotlib.pyplot as plt
import seaborn as s
import numpy as n


# In[2]:


import warnings
warnings.filterwarnings('ignore')


# In[3]:


# feature names
features = ["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land", "Wrong_fragment", "Urgent", "hot", "num_failed_login", "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_ srv_rate", "dst_host_same_src_port_rate", "dst_host_srv_diff_host _rate", "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate","class"] 
df = p.read_csv("demo3.csv", names = features)
print(df.shape)


# In[4]:


df.head()


# In[5]:


df['class'].unique()


# In[6]:


df.head()


# In[7]:


from tkinter import *


# In[8]:


del df["duration"]
del df["land"]
del df["Urgent"]
del df["hot"]
del df["num_failed_login"]
del df["logged_in"]
del df["num_compromised"]
del df["root_shell"]
del df["is_host_login"]
del df["is_guest_login"]


# In[9]:


del df['num_root']
del df['num_file_creations']
del df['num_shells']
del df['num_outbound_cmds']
del df['count']
del df['srv_count']
del df['srv_serror_rate']
del df['srv_rerror_rate']
del df['same_srv_rate']
del df['diff_srv_rate']
del df['srv_diff_host_rate']
del df['dst_host_count']
del df['dst_host_srv_count']
del df['dst_host_same_srv_rate']
del df['dst_host_diff_ srv_rate']
del df['dst_host_same_src_port_rate']
del df['dst_host_srv_diff_host _rate']
del df['dst_host_serror_rate']
del df['dst_host_srv_serror_rate']
del df['dst_host_rerror_rate']
del df['dst_host_srv_rerror_rate']

del df['su_attempted']
del df['num_access_files']


# In[10]:


df.columns


# In[11]:


df['protocol_type'].unique()


# In[12]:


df['UDP'] = df.protocol_type.map({'udp':1, 'tcp':0, 'icmp':0})
df['TCP'] = df.protocol_type.map({'udp':0, 'tcp':1, 'icmp':0})
df['ICMP'] = df.protocol_type.map({'udp':0, 'tcp':0, 'icmp':1})


# In[13]:


del df['protocol_type']


# In[14]:


df['service'].unique()


# In[15]:


df['private'] = df.service.map({'ecr_i':0, 'http':0, 'private':1})

df['http'] = df.service.map({'ecr_i':0, 'http':1, 'private':0})



# In[16]:


df['ecr_i'] = df.service.map({'ecr_i':1, 'http':0, 'private':0})



# In[17]:


df['http'].unique()


# In[18]:


del df['service']


# In[19]:


df['flag'].unique()


# In[20]:


df['SF'] = df.flag.map({'SF':1, 'S0':0, 'REJ':0, 'S1':0})
df['S1'] = df.flag.map({'SF':0, 'S0':0, 'REJ':0, 'S1':1})
df['REJ'] = df.flag.map({'SF':0, 'S0':0, 'REJ':1, 'S1':0})
df['S0'] = df.flag.map({'SF':0, 'S0':0, 'REJ':0, 'S1':1})


# In[21]:


df['S0'].unique()


# In[22]:


del df['flag']


# In[23]:


df.columns


# In[24]:


df['src_bytes'].unique()


# In[25]:


df['SRC_BY_BL_50'] = df.src_bytes.map({1032:0,  283:0,  252:0,    0:1,  105:0,  303:0,   42:1,   45:1,  213:0,  285:0, 5050:0,
        212:0,  184:0,  289:0,  291:0,  246:0,  175:0,  241:0,  293:0,  245:0,  249:0,  225:0,
        305:0, 3894:0,  320:0,  162:0,  206:0,  353:0,    1:1})
df['SRC_BY_AB_50'] = df.src_bytes.map({1032:0,  283:0,  252:0,    0:0,  105:1,  303:0,   42:0,   45:0,  213:0,  285:0, 5050:0,
        212:1,  184:1,  289:0,  291:0,  246:1,  175:1,  241:1,  293:0,  245:1,  249:1,  225:1,
        305:0, 3894:0,  320:0,  162:1,  206:1,  353:0,    1:0})
df['SRC_BY_AB_250'] = df.src_bytes.map({1032:0,  283:1,  252:1,    0:0,  105:1,  303:0,   42:0,   45:0,  213:0,  285:1, 5050:0,
        212:0,  184:0,  289:1,  291:1,  246:0,  175:1,  241:0,  293:1,  245:0,  249:0,  225:0,
        305:1, 3894:0,  320:1,  162:1,  206:0,  353:1,    1:0})

df['SRC_BY_AB_450'] = df.src_bytes.map({1032:0,  283:1,  252:1,    0:0,  105:0,  303:0,   42:0,   45:0,  213:1,  285:1, 5050:0,
        212:1,  184:0,  289:1,  291:1,  246:1,  175:0,  241:1,  293:1,  245:1,  249:1,  225:1,
        305:0, 3894:0,  320:0,  162:0,  206:1,  353:0,    1:0})


df['SRC_BY_AB_650'] = df.src_bytes.map({1032:0,  283:0,  252:0,    0:0,  105:0,  303:0,   42:0,   45:0,  213:0,  285:0, 5050:0,
        212:0,  184:0,  289:0,  291:0,  246:0,  175:0,  241:0,  293:0,  245:0,  249:0,  225:0,
        305:0, 3894:0,  320:0,  162:0,  206:0,  353:0,    1:0})

df['SRC_BY_AB_850'] = df.src_bytes.map({1032:0,  283:0,  252:0,    0:0,  105:0,  303:0,   42:0,   45:0,  213:0,  285:0, 5050:0,
        212:0,  184:0,  289:0,  291:0,  246:0,  175:0,  241:0,  293:0,  245:0,  249:0,  225:0,
        305:0, 3894:0,  320:0,  162:0,  206:0,  353:0,    1:0})

df['SRC_BY_AB_1000'] = df.src_bytes.map({1032:1,  283:0,  252:0,    0:0,  105:0,  303:0,   42:0,   45:0,  213:0,  285:0, 5050:1,
        212:0,  184:0,  289:0,  291:0,  246:0,  175:0,  241:0,  293:0,  245:0,  249:0,  225:0,
        305:0, 3894:1,  320:0,  162:0,  206:0,  353:0,    1:0})



# In[26]:


del df['src_bytes']


# In[27]:


df.columns


# In[28]:


df['dst_bytes'].unique()


# In[29]:


df['DST_BY_BL_50'] = df.dst_bytes.map({   0:1,   903:0,  1422:0,   146:0,  1292:0,    42:1,   115:0,  4996:0,   145:0,
        5200:0,   329:0,   341:0,   128:0,   721:0,   331:0,   753:0, 38352:0,   722:0,
        1965:0,   634:0,   628:0,   188:0, 47582:0,   489:0,   105:0,   486:0,  2940:0,
         209:0,  1401:0,   292:0,  1085:0,     1:1})


df['DST_BY_AB_50'] = df.dst_bytes.map({   0:0,   903:0,  1422:0,   146:1,  1292:0,    42:0,   115:1,  4996:0,   145:1,
        5200:0,   329:0,   341:0,   128:1,   721:0,   331:0,   753:0, 38352:0,   722:0,
        1965:0,   634:0,   628:0,   188:1, 47582:0,   489:0,   105:1,   486:0,  2940:0,
         209:1,  1401:0,   292:1,  1085:0,     1:0})

df['DST_BY_AB_250'] = df.dst_bytes.map({   0:0,   903:0,  1422:0,   146:0,  1292:0,    42:0,   115:0,  4996:0,   145:0,
        5200:0,   329:1,   341:1,   128:0,   721:0,   331:1,   753:0, 38352:0,   722:0,
        1965:0,   634:0,   628:0,   188:0, 47582:0,   489:0,   105:0,   486:0,  2940:0,
         209:1,  1401:0,   292:1,  1085:0,     1:0})

df['DST_BY_AB_450'] = df.dst_bytes.map({   0:0,   903:0,  1422:0,   146:0,  1292:0,    42:0,   115:0,  4996:0,   145:0,
        5200:0,   329:0,   341:0,   128:0,   721:0,   331:0,   753:0, 38352:0,   722:0,
        1965:0,   634:1,   628:1,   188:0, 47582:0,   489:1,   105:0,   486:1,  2940:0,
         209:0,  1401:0,   292:0,  1085:0,     1:0})

df['DST_BY_AB_650'] = df.dst_bytes.map({   0:0,   903:0,  1422:0,   146:0,  1292:0,    42:0,   115:0,  4996:0,   145:0,
        5200:0,   329:0,   341:0,   128:0,   721:1,   331:0,   753:1, 38352:0,   722:1,
        1965:0,   634:0,   628:0,   188:0, 47582:0,   489:0,   105:0,   486:0,  2940:0,
         209:0,  1401:0,   292:0,  1085:0,     1:0})

df['DST_BY_AB_850'] = df.dst_bytes.map({   0:0,   903:1,  1422:0,   146:0,  1292:0,    42:0,   115:0,  4996:0,   145:0,
        5200:0,   329:0,   341:0,   128:0,   721:0,   331:0,   753:0, 38352:0,   722:0,
        1965:0,   634:0,   628:0,   188:0, 47582:0,   489:0,   105:0,   486:0,  2940:0,
         209:0,  1401:0,   292:0,  1085:0,     1:0})

df['DST_BY_AB_1000'] = df.dst_bytes.map({   0:0,   903:0,  1422:1,   146:0,  1292:1,    42:0,   115:0,  4996:1,   145:0,
        5200:1,   329:0,   341:0,   128:0,   721:0,   331:0,   753:0, 38352:1,   722:0,
        1965:1,   634:0,   628:0,   188:0, 47582:1,   489:0,   105:0,   486:0,  2940:1,
         209:0,  1401:0,   292:0,  1085:1,     1:0})



# In[30]:


df['DST_BY_AB_1000'].unique()


# In[31]:


del df['dst_bytes']


# In[32]:


del df['Wrong_fragment']
del df['serror_rate']
del df['rerror_rate']


# In[33]:


df.head()


# In[34]:


df.columns


# In[35]:


l1=['SRC_BY_BL_50', 'SRC_BY_AB_50', 'SRC_BY_AB_250','SRC_BY_AB_450', 'SRC_BY_AB_650', 'SRC_BY_AB_850', 'SRC_BY_AB_1000']


# In[36]:


l2=['DST_BY_BL_50', 'DST_BY_AB_50', 'DST_BY_AB_250', 'DST_BY_AB_450','DST_BY_AB_650', 'DST_BY_AB_850', 'DST_BY_AB_1000']


# In[37]:


l3=['UDP', 'TCP', 'ICMP']


# In[38]:


l4=['SF', 'S1', 'REJ', 'S0']


# In[39]:


l5=['private','http', 'ecr_i']


# In[40]:


l6=['UDP', 'TCP', 'ICMP', 'private', 'http', 'ecr_i', 'SF', 'S1','REJ', 'S0', 'SRC_BY_BL_50', 'SRC_BY_AB_50', 'SRC_BY_AB_250',
'SRC_BY_AB_450', 'SRC_BY_AB_650', 'SRC_BY_AB_850', 'SRC_BY_AB_1000',
'DST_BY_BL_50', 'DST_BY_AB_50', 'DST_BY_AB_250', 'DST_BY_AB_450','DST_BY_AB_650', 'DST_BY_AB_850', 'DST_BY_AB_1000']


# In[41]:


df['class'].unique()


# In[42]:


decision = ['smurf', 'perl', 'xlock', 'xsnoop', 'xterm', 'satan', 'neptune','nmap', 'back', 'apache2', 'multihop', 'worm',
'buffer overflow','sql attack', 'saint', 'Nmap', 'ipsweep']


# In[43]:


l7=[]
for x in range(0,len(l6)):
    l7.append(0)


# In[44]:


df['class'].unique()


# In[45]:


df.replace({'class':{'smurf':0, 'perl':1, 'xlock':2, 'xsnoop':3, 'xterm':4, 'satan':5, 'neptune':6,
       'nmap':7, 'back':8, 'apache2':9, 'multihop':10, 'worm':11, 'buffer overflow':12,
       'sql attack':13, 'saint':14, 'Nmap':15, 'ipsweep':16}},inplace=True)


# In[46]:


import numpy as np


# In[47]:


Xd= df[l6]


yd = df[["class"]]
np.ravel(yd)


# In[48]:


import numpy as np
X_testd= df[l6]
y_testd = df[["class"]]
np.ravel(y_testd)


# In[49]:


from sklearn.svm import SVC
from sklearn.model_selection import cross_val_score
from sklearn.metrics import accuracy_score


# In[50]:


def over():
  
   
    clf = SVC()

    gnb=clf.fit(Xd,np.ravel(yd))

    # calculating accuracy-------------------------------------------------------------------
    from sklearn.metrics import accuracy_score
    y_predd=gnb.predict(X_testd)
    print(accuracy_score(y_testd, y_predd))
    
    print(accuracy_score(y_testd, y_predd,normalize=False))
   
    # -----------------------------------------------------
    terms = [src.get(),dst.get(),prt.get(),fl.get(),ser.get()]

    
    for k in range(0,len(l6)):
        for z in terms:
            if(z==l6[k]):
                l7[k]=1

    inputtest = [l7]
    predict = gnb.predict(inputtest)
    predicted=predict[0]

    h='no'
    for a in range(0,len(decision)):
        if(predicted == a):
            h='yes'
            break

    if (h=='yes'):
        t1.delete("1.0", END)
        t1.insert(END, decision[a])
    else:
        t1.delete("1.0", END)
        t1.insert(END, "Not Found")




# In[51]:


root1 = Tk()
root1.title("Prediction of Network Attacks")
#root1.configure(background='black')


# In[52]:


root = Canvas(root1,width=1620,height=1800)
root.pack()
photo = PhotoImage(file ='im3.png')
root.create_image(0,0,image=photo,anchor=NW)


# In[53]:


src = StringVar()
src.set(None)

dst = StringVar()
dst.set(None)

prt = StringVar()
prt.set(None)

fl = StringVar()
fl.set(None)

ser = StringVar()
ser.set(None)


# In[54]:


# Heading
w2 = Label(root, justify=LEFT, text="Network attack prediction ", fg="red", bg="white")
w2.config(font=("Elephant", 20))
w2.grid(row=1, column=0, columnspan=2, padx=100)
w2 = Label(root, justify=LEFT, text="DoS, R2L, U2R and Probe Types ", fg="blue")
w2.config(font=("Aharoni", 15))
w2.grid(row=2, column=0, columnspan=2, padx=100)



# In[55]:


# labels
srcLb = Label(root, text="Source File Size(in BY):")
srcLb.grid(row=6, column=0, pady=15, sticky=W)

dstLb = Label(root, text="Destination File Size(in BY):")
dstLb.grid(row=7, column=0, pady=15, sticky=W)

prtLb = Label(root, text="Protocol Type:")
prtLb.grid(row=8, column=0, pady=15, sticky=W)

flLb = Label(root, text="Flag Type:")
flLb.grid(row=9, column=0, pady=15, sticky=W)

serLb = Label(root, text="Select services:")
serLb.grid(row=10, column=0, pady=15, sticky=W)


# In[56]:


lrdLb = Label(root, text="Attack_Type", fg="white", bg="red")
lrdLb.grid(row=13, column=0, pady=10, sticky=W)


# In[57]:


# entries
OPTIONSsrc = sorted(l1)
OPTIONSdst = sorted(l2)
OPTIONSprt = sorted(l3)
OPTIONSfl = sorted(l4)
OPTIONSser = sorted(l5)


# In[58]:


srcEn = OptionMenu(root, src,*OPTIONSsrc)
srcEn.grid(row=6, column=1)

dstEn = OptionMenu(root, dst,*OPTIONSdst)
dstEn.grid(row=7, column=1)

prtEn = OptionMenu(root, prt,*OPTIONSprt)
prtEn.grid(row=8, column=1)

flEn = OptionMenu(root, fl,*OPTIONSfl)
flEn.grid(row=9, column=1)

serEn = OptionMenu(root, ser,*OPTIONSser)
serEn.grid(row=10, column=1)


# In[59]:


def clear_display_result():
    t1.delete('1.0',END)


# In[60]:


lrd = Button(root, text="Check Result", command=over,bg="cyan",fg="green")
lrd.grid(row=13, column=3,padx=10)
b = Button(root, text="Reset", command=clear_display_result,bg="red",fg="white")
b.grid(row=5, column=3,padx=10)


# In[ ]:


t1 = Text(root, height=1, width=40,bg="orange",fg="black")
t1.grid(row=13, column=1 , padx=10)
root1.mainloop()


# In[ ]:





# In[ ]:




