# Assignment 0: Getting start
## Due Oct 2, 2020, 11:59PM (GMT+8)
### Course Info

---

Computer Network, Nanjing University, fall 2020

Lecturer: [Yuan Zhang](http://cosec.nju.edu.cn/#index.php/members/yuan-zhang)

Course QQ group: 836587931


Lecturer: [Jiaqi Zheng](https://cs.nju.edu.cn/jzheng/)

Course QQ group: 808051921

Our lab assignments are based on CS640 in University of Wisconsin. Most materials are the same. In the future, we will improve the experiment based on your feedback.

In this lab assignment, you will gradually master our experimental environment. But some preliminary abilities are required in our experiments such as how to program and debug in Linux. If you are not familiar with these, feel free to contact TAs. We will provide you with some helpful information to get started quickly.

---

### Part 0 Build your coding environment

You SHOULD have a coding environment involving `gcc/g++` `python` `git` `python3` and be able to link `dynamic lib`. If not, we recommend you using [Ubuntu](https://ubuntu.com/download/desktop). If you don't have Ubuntu, you can use a virtual machine (VM) like [VirtualBox](https://www.virtualbox.org/wiki/Downloads) or [VMware](https://www.vmware.com/cn/products/workstation-player/workstation-player-evaluation.html). It's easy to install Ubuntn in VM, please try to do it. 
If the download speed is slow during the installation, you can skip it and change the source mirror later. [Here](https://juejin.im/post/6844904062526160909) is a tutorial.

In the following part of this and many next README files, the notation:
+ `$: command line in Ubuntu/Debian Terminal`
+ `#: some commends/description`
+ `mininet> commands in Mininet`
+ `'something_more' ''`

After you set up your Ubuntu system,

`
$ sudo apt-get install cmake g++ git python3-dev qt5-qmake qt5-default python python3
`

You can choose any IDE or tools you like to code.If you don't know how to choose, we have two recommendations.

You can use Visual Studio Code (VSC) to develope your projects.The easiest way to install Visual Studio Code for Debian/Ubuntu based distributions is to download and install the [.deb package (64-bit)](https://go.microsoft.com/fwlink/?LinkID=760868), either through the graphical software center if it's available, or through the command line with:

```
$ sudo apt install ./<file>.deb
``` 
After install, you can use the command `$code` to open a new VSC window or `$code <filename>` to open file with VSC.


Or you can choose [anaconda](https://www.anaconda.com/distribution/#download-section) as the python developing toolkit with [Jupyter Notebook](https://jupyter.org/install).
Jupyter-Notebook can provide a `.ipynb` file helping you run a real-time feedback python script. 
````
(Warning) the following steps may not work on some computers
TRY to solve them and feel free to contact TAs(TAs: No, we are not free, DO it YOURSELF).

$ cd ~/Desktop
$ mkdir temp
$ cd temp

$ wget https://repo.anaconda.com/archive/Anaconda3-2019.07-Linux-x86_64.sh

# Instead of wget you may also download this file manually
# https://www.anaconda.com/distribution/#download-section
# then choose Python3.7 version Linux 64bit x86 installer

$ sudo chmod u+x Anaconda3-2019.07-Linux-x86_64.sh
$ sudo ./Anaconda3-2019.07-Linux-x86_64.sh
# Then follow the Installation step

# reboot your system | $ sudo reboot

# After reboot type $ conda , then maybe the Terminal will return an error command
# This is caused with missing link Conda to Terminal -> you can add PATH to .bashrc or source
$ echo 'export PATH="/<conda's path>/bin:$PATH"' >> ~/.bashrc
$ source ~/.bashrc
# If any other questions, please google/baidu it and try to solve them
# After that don't forget $ conda init bash  #for Ubuntu only
# You should see (base) ...$  

(Optional) you should set a individual workspace for your python/conda environment
Something like $ conda create -n your_env_name python=3.7
If you wanna use this envs -> activate it $ conda activate your_env_name
if you need to see all your environments $ conda info --envs (多个环境独立使用可以起到隔离保护的作用)

# In (Base) or (your_env_name) to install Jupyter notebook
$ conda install jupyter jupyter notebook python
$ jupyter notebook

If you meet the IMPORT error you can install missing lib via $ conda install 'missing_lib'
Or $ pip install 'missing_lib'
(Clearly the best way is to Google the solution)
````
### Part 1 Git and GitHub
How to use git && GitHub:

Register a GitHub account if you haven't, then:
````
$ git config --global user.name "YOUR-SCREEN-NAME"
$ git config --global user.email YOUR-EMAIL-ADDRESS
````
Feel free to get more [infomation](https://git-scm.com/book/zh/v2)

You will receive your homework assignments, accept it then you will get a git repo whose link as `YOUR_HW_LINK`(i.e. https://github.com/NJUCS-Networklabs-20fall/assignment-number-your_screen_name)

**Please ALERT the DDL, GitHub will close automatically**
````
$ cd ~/Desktop/
$ mkdir hw
$ cd hw`
$ git clone YOUR_HW_LINK
# maybe need your GitHub account and passwords

# Code with FUN!!!
# ONLY KEEP CHANGE IN YOUR ASSIGNMENT-NUMBER FOLDER
# BECAUSE GIT ONLY SUBMIT WHAT'S IN THE FOLDER (.git)

# Once you finished
# In the ASSIGNMENT-NUMBER folder
$ git add -A
$ git commit -m "some words/marks"
$ git push origin master
# maybe need your GitHub account and passwords
````

例如当你git clone Assignment-0-your_screen_name后在文件夹中有这个README以及一个文件(还有一个.git/含有git branch的控制信息)


### Part 2 Who are you
注意 请将该目录下的文件改名为 你的中文姓名-你的学号 （注意中间有个-） 、
完成后,在Assignment-0-your_screen_name这个文件夹下：
````
$ git add -A
$ git commit -m "你的姓名(中英文随意)"
$ git push origin master
````
**[NOTE]**
We may check your abnormal work by your commit, so git commit -m 'what you do by this commit' in future assignment.  
