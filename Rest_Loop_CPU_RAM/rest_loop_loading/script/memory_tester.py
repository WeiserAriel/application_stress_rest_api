import requests
import logging
import datetime
import traceback
import time
from time import sleep
import sys
import paramiko
import csv
import re
import threading
import optparse
import json
import os
import shutil
import matplotlib
matplotlib.use('agg')
from matplotlib import pyplot as plt
from matplotlib import style
import numpy as np
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders


#TODO -
'''
1. Creating graphs every hour
2. run script with NEO process + sending REST API in background+ generating reports. 
3. sending the graphs via email 
'''



#consts
global_csv_path = str(os.path.abspath(__file__)).split("script")[0] + "csv" + os.sep
global_graphs_path = str(os.path.abspath(__file__)).split("script")[0] + "graphs" + os.sep
global_ram_path = os.path.join(global_csv_path, 'RestAPI_loop_ram.csv')
global_cpu_path = os.path.join(global_csv_path, 'RestAPI_loop_cpu.csv')
global_requests_path = os.path.join(global_csv_path, 'RestAPI_loop_requests.csv')
timer1 = None
timer2 = None
stop = False
total = 0
ufm_processes_name_list = ['mysqld','opensm','ModelMain','periodic_report_runner','unhealthy_ports_main','ibpm','UFMHealthConfiguration']
neo_processes_name_list = ['ac_service','sdn_controller','dm_service','eth_discovery_service','nhm_service',\
                           'ib_service','ip_discovery_service','monitor_service','perf_service',\
                           'prov_service','solution_service','telemetry_service','virtualization_service']

def send_email_to_recipient(email_send, product_type,total_time):
    email_user = 'memory.tester1234@gmail.com'
    email_password = '2wsx@WSX'
    subject = 'Memory tester results for ' + product_type

    msg = MIMEMultipart()
    msg['From'] = email_user
    msg['To'] = email_send
    msg['Subject'] = subject

    body = 'Hi there, here are the results for '+ product_type + '\ntotal time for test is:' + str(total_time) +' hours.'
    msg.attach(MIMEText(body, 'plain'))
    last_directory = [x[0] for x in os.walk(global_graphs_path)].pop()
    attached_files = os.listdir(last_directory + os.sep)
    for filename in attached_files:
        logging.info("Sending last result for " + email_send)
        try:
            full_path= last_directory +os.sep +filename
            attachment = open(full_path, 'rb')

            part = MIMEBase('application', 'octet-stream')
            part.set_payload((attachment).read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', "attachment; filename= " + filename)
            msg.attach(part)
            text = msg.as_string()
        except Exception as e:
            print("exception in sending graphs via email\n" + str(e))
        logging.info("All graphs were sent to " + email_send + " successfully")

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(email_user, email_password)
    if attached_files:
        server.sendmail(email_user, email_send, text)
    server.quit()

def create_ufm_health_report(ip, username, password):
    counter = 1
    url = 'http://$ip/ufmRest/reports/Fabric_Health'
    url = url.replace('$ip',ip)
    ufm_payload =r"""
    {
        "duplicate_nodes": true,
        "map_guids_desc": false,
        "ufm_alarms": true,
        "sm_state": true,
        "firmware": true,
        "cables": false,
        "non_opt_links": true,
        "non_opt_speed_width": true,
        "link_speed": "ALL",
        "link_width": "ALL",
        "eye_open": false,
        "duplicate_zero_and_lids": true
    }
    """
    while not stop:
        logging.debug( str(counter) + "# Sending Fabric Health Report...")
        r = requests.post(url = url, auth=(username, password), data=ufm_payload)
        if str(r.status_code) == '202':
            logging.info(str(counter) + "# Sending Fabric Health Report successfully...")
        else:
            logging.error("Fabric Health Failed... status code equals {}".format(str(r.status_code)))
        counter+=1
        
        
def creating_directory(path):
    logging.debug("Start to create directory inside " + str(path))
    #Try to remove backslash from the end:
    path = path.rstrip()
    try:
        if os.path.exists(path):
            shutil.rmtree(path)
        os.mkdir(path)
    except OSError as ex:
        logging.error("Creation of the directory failed" +str(ex))
        sys.exit(1)
    else:
        logging.info("Successfully created the directory %s " % path)


def findRegex(output, regex_search):
    pattern =re.compile(pattern=regex_search)
    matches_list = pattern.findall(source=output)
    if len(matches_list) > 0:
        logging.debug("Regex:" + regex_search + " Was found!")
        return matches_list
    else:
        logging.critical("Regex was not found!:" + regex_search )
        return []

def createshell(ssh):
    shell = ssh.invoke_shell()
    shell.settimeout(0.5)
    shell.recv(1024)
    #time.sleep(10)
    return shell

def run_par_cmd(cmd, expect, shell):
    '''

      :param shell:
      :param cmd: cmd command like ' show version'
      :param expect: string to look for like '
      :return: 0 if the expected string was found in output.
      '''
    # sleeping for 3 seconds to the command will be executed after shell prompt is printed.
    shell.send(cmd + '\n')
    out = ''
    while True:
        try:
            tmp = shell.recv(1024)
            if not tmp:
                break
        except Exception as e:
            break
        out += tmp.decode("utf-8")
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    out = ansi_escape.sub('', out)
    if expect not in out:
        return (1, out)
    return (0, out)


def SSHConnect(ip,username, passowrd):
    ssh = paramiko.SSHClient()
    logging.debug(msg="Open SSH Client to :" + str(ip))
    try:
        ssh.set_missing_host_key_policy(policy=paramiko.AutoAddPolicy())
        ssh.connect(ip, port=22, username=username, password=passowrd, allow_agent=False, look_for_keys=False)
    except Exception as ex:
        logging.error(msg="SSH Client wasn't established!")
        sys.exit(0)
    logging.info(msg="Open SSH Client to :" + str(ip) + "established!")
    return ssh

def ChangeToShellMode(shell):
    #result should be '0'
    result = run_enable_configure_terminal(shell)
    if int(result) != 0:
        logging.error("Can't run \'_shell\' command..\n" + "exiting")
        exit(1)
    else:
        command = "_shell"
        expect = '~]#'
        try:
            logging.debug("Changing UFM APL from CLI Mode to SHELL mode")
            result, output = run_par_cmd(cmd=command, expect=expect, shell=shell)
        except Exception as ex:
            logging.error("Got Exception while trying to change for SHELL mode" + str(ex))
        if int(result) == 0:
            logging.debug("_shell command was executed successfully!")
        else:
            logging.error("couldn't find expected output while running shell command..\nPlease make sure License is installed!")

def get_ram_total_used(output, regex_ram, counter):
    matches = findRegex(output, regex_ram)
    if matches:
        cpu_value_total, cpu_value_used = matches[0][2], matches[0][4]
        logging.debug(str(counter) + "# RAM value is :\t" + str((float(cpu_value_used)/float(cpu_value_total))*100)+'%')
        return float(cpu_value_used)/float(cpu_value_total)
    else:
        logging.error("Couldn't retrived RAM usage according to given regex!")
        return -1

def GetRAMUsage(shell ,counter):
    command = r"""free -t"""
    expected = 'total'
    mode ='a'
    regex_ram = r'([Total:]{6})(\s*)(\d*)(\s*)(\d*)'
    if counter == 0:
        mode = 'w'

    #file = os.path.realpath(__file__) + os.sep + '..' + os.sep + os.path.join('csv' , 'RestAPI_loop_ram.csv')
    with open(global_ram_path, mode, newline='') as csvfile:
        fieldnames = ['iteration number', 'RAM']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        time_started = datetime.datetime.now()
        try:
            logging.debug("Measuring RAM USage...")
            result, output = run_par_cmd(cmd=command, expect=expected, shell=shell)
        except Exception as ex:
            logging.error("Got Exception while trying to retrieve RAM utilization , " + str(ex))
            print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(ex).__name__, ex)
        else:
            if int(result) == 0:
                logging.debug( str(counter) +"# get RAM command was executed successfully!")
            else:
                logging.error("couldn't find expected output while running \'free -t\' command..\n")
                print("expected: " + expected + '\n' +"Output : \n" + output+'\n\n')
                return None
            ram_total = str(get_ram_total_used(output, regex_ram, counter))
            if  str(ram_total) == '-1' :
                logging.error("Couldn't calculate RAM usage")
                return None
            else:
                writer.writerow({'iteration number': counter, 'RAM': str(float(ram_total)*100)})
        csvfile.close()

def GetCPUUsage(shell, counter):
    command = r"""mpstat"""
    expected = 'CPU'
    regex = r'([0-9]{1,4})(\.)([0-9]{1,4})'
    mode ='a'
    if counter == 0:
        mode = 'w'
    #file = os.path.realpath(__file__) + os.sep + '..' + os.sep +  os.path.join( 'csv', 'RestAPI_loop_cpu.csv')
    with open(global_cpu_path ,mode=mode, newline='') as csvfile:
        fieldnames = ['iteration number', 'CPU']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        time_started = datetime.datetime.now()
        try:
            logging.debug("Measuring CPU USage...")
            result, output = run_par_cmd(cmd=command, expect=expected, shell=shell)
        except Exception as ex:
            logging.error("Got Exception while trying to retrieve CPU utilization , " + str(ex))
        else:
            if int(result) == 0:
                logging.debug("CPU command was executed successfully!")
            else:
                logging.error("couldn't find expected output while running CPU command..")
                return None
            cpu_value = findRegex(output ,regex)
            if cpu_value:
                #Change tuple to string
                cpu_value_flt =100 - float(''.join(cpu_value[len(cpu_value) - 1]))
                if 0.0 <= cpu_value_flt <= 100.0:
                #if cpu_value_str <= 100.0 and cpu_value_str >= 0.0:
                    logging.debug( str(counter)+ "# CPU usage is:\t " + str(cpu_value_flt) + '%')
                    writer.writerow({'iteration number': str(counter), 'CPU': str(cpu_value_flt)})
                else:
                    logging.error("Not Matched Regex!\nCouldn't retrevied CPU usage according to given regex!")
            else:
                logging.error("Couldn't retrieved CPU usage!")
        csvfile.close()

def messurement_host_performance(shells, loops):

    i1 = 0
    lst = []
    while stop == False:
        try:
            logging.debug("Running CPU/RAM performance test #"+ str(i1))
            t1 = threading.Thread(target=GetCPUUsage,  args=(shells[0],i1))
            t2 = threading.Thread(target=GetRAMUsage, args=(shells[1],i1))
            t1.start()
            t2.start()
            t1.join()
            t2.join()
            i1+=1
        except Exception as ex:
            print("Threads number: " + str(threading.active_count()) +str(ex))
            logging.error("Exception on starting thread" + str(ex))
    logging.info("Performance measurement is completed!")

def run_enable_configure_terminal(shell):
    commandsList = ['enable' , 'configure terminal']
    expectedList = ['#', '(config)']
    for cmd,expect in zip(commandsList,expectedList):
        result, output = run_par_cmd(cmd=cmd, expect=expect, shell=shell)
        if ((int(result) == 0 )and (len(output) > 0 )):
            logging.info(cmd+ " command run successfully")
        else:
            logging.error("can't run "+cmd+" command")
            sys.exit(1)
    return False

def get_vmsize_of_process_by_process_id(shell, process_vm):
    cmd = 'cat /proc/x/status'
    cmd = str(cmd).replace('x',process_vm)
    expected = 'VmSize'
    regex_search='(VmSize:)(\s*)(\d*)(\s*)(kB)'
    vm_size = None

    result, output = run_par_cmd(cmd, expected,shell)
    if ((int(result) == 0) and (len(output) > 0)):
        logging.debug(cmd + " command run successfully")
    else:
        logging.error("can't run " + cmd + " command")
        sys.exit(1)
    matches = findRegex(output, regex_search)
    if matches:
        vm_size = str(matches[0][2])
    else:
        logging.error("No matches were found for vmsize")
    return vm_size
def continue_loop(counter,started_time, loops, time):
    if time is not None:
        if (started_time + datetime.timedelta(hours=int(time)) > datetime.datetime.now()):
            return True
        else:
            return False
    else:
        if loops is not None:
            if (int(counter) < int(loops)):
                return True
            else:
                return False
def send_ufm_rest_get_pkey(shell,product_type, ip, username, password, private_key_path,certificate_path):

    url = r'http://ip/ufmRest/actions/get_all_pkeys'
    url = url.replace('ip',ip)
    s = requests.session()
    s.auth = (username, password)
    if ((private_key_path is not None) and (certificate_path is not None)):
        # Using SSL certification
        s.cert = (certificate_path, private_key_path)
    else:
        logging.debug("Using Basic Authentication")
    try:
        logging.debug("creating new pkey with rest request ")
        r = s.get(url= url)
    except Exception as e:
        logging.error("exception in UFM rest request")
    logging.info("creating new pkey with rest request was send successfully.")
    return r

def run_rest_in_loop(shell,ip, prodcut_type, loops,time, username, password, private_key_path, certificate_path):
    counter = 0
    success = 0
    time_started = datetime.datetime.now()

    #file = os.path.realpath(__file__) + os.sep +'..' + os.sep + os.path.join('csv', 'RestAPI_loop_requests.csv')
    with open(global_requests_path, 'w', newline='') as csvfile:
        fieldnames = ['iteration number', 'time', 'Response Code', 'Succeeded']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        while continue_loop(counter,time_started,loops,time):
            request_send_time = datetime.datetime.now()
            logging.debug(str(counter) + "# sending Rest request")
            counter += 1
            try:
                if (prodcut_type == 'ufm' or prodcut_type == 'ufmapl'):
                    r = send_ufm_rest_get_pkey(shell,prodcut_type,ip,username,password,private_key_path,certificate_path)
                elif (prodcut_type == 'neo'):
                    r = send_neo_ports_rest_api(ip)
            except Exception as ex:
                logging.error("Exception on sending REST request" + str(counter) + "\n" + str(ex))
                sys.exit(1)
            request_end_time = datetime.datetime.now()
            total_requst_time = str(request_end_time - request_send_time)
            request_status_code = r.status_code
            if (str(r.status_code) == '200'):
                success += 1
                writer.writerow(
                    {'iteration number': str(counter), 'time': str(time_started), 'Response Code': str(request_status_code),
                     'Succeeded': 'Yes'})
                logging.info("Total time for request #" + str(counter) + " is\t " + total_requst_time)
            else:
                logging.error("Request # " + str(counter) + " Failed!" + "Status Code is: " + str(request_status_code))
                writer.writerow(
                    {'iteration number': counter, 'time': total_requst_time, 'Response Code': request_status_code,
                     'Succeeded': 'No'})
        csvfile.close()
    end_time = datetime.datetime.now()
    total_time = end_time - time_started
    logging.info("Total time for " + str(counter) + ' loops' + " was\t\t\t" + str(total_time) + "\t\tNumber of Success Requests:\t " + str(success) + "/" + str(counter))
    global stop
    stop = True


def virtual_memory_of_processes(shell, loops, product_type):
    ufm_base_regex = r"""(\s{1,6})(\d{1,6})(\s{1,6})(\d*)(\s*)(\d*)(.*)(ufm/)(.*)"""
    neo_base_regex = r"""(\s{1,6})(\d{1,6})(\s{1,6})(\d*)(\s*)(\d*)(.*)(neo/)(.*)"""
    global ufm_processes_name_list
    global neo_processes_name_list
    if (product_type == 'neo'):
        proccess_list = neo_processes_name_list
        base_regex = neo_base_regex
    else:
        proccess_list = ufm_processes_name_list
        base_regex = ufm_base_regex
    logging.debug(" Running ps -ef command to check running processes")
    if (product_type == 'ufmapl'):
        # running ps -ef | grep ufm and not ps -ef | grep ufmapl
        product_type = 'ufm'
    expected = product_type
    command = 'ps -ef | grep '+ product_type
    i=0

    while stop == False:
        try:
            result, output = run_par_cmd(cmd=command, expect=expected, shell=shell)
        except Exception as ex:
            logging.error("exception in ps -ef command")
        if int(result) != -1:
            for process_name in proccess_list:
                regex_search = base_regex + '('+process_name + ')'
                matches = findRegex(output, regex_search)
                if matches:
                    process_vm = str(matches[0][1])
                    vm_size = get_vmsize_of_process_by_process_id(shell, process_vm)
                    logging.debug( str(i) + "# virtual memory of " + str(process_name) + " = " + str(vm_size))
                    write_process_to_csv(i, process_name,vm_size)
                else:
                    logging.error("couldn't find process virtual memory according to given regex")
            logging.info( str(i) + "# vmsize of all Processes were written to csv ")
            i += 1
        else:
            logging.error("couldn't find expected result in ps -ef command")
def get_product_name_by_url(url):

    if int(str(url).find('ufm')) != -1:
        return 'ufm'
    elif int(str(url).find('neo')) != -1:
        return 'neo'
    else:
        return -1

def create_graphs(product_type):
    global ufm_processes_name_list
    global neo_processes_name_list
    if product_type == 'neo':
        proccess_list = neo_processes_name_list
    else:
        proccess_list = ufm_processes_name_list

    logging.info("Creating Graphs for processes")

    dt = str(datetime.datetime.now()).split(".")[0].replace(" ","_").replace(":","-")
    #Creating sub folder for graphs_time
    current_graph_folder = global_graphs_path + dt + os.sep
    creating_directory(current_graph_folder)

    for process_name in proccess_list:
        filename = global_csv_path + 'RestAPI_loop_' + str(process_name) + '.csv'
        create_graph(filename, str(process_name), 'VMSize(kb)','iterations',current_graph_folder,process_name )
    logging.info("Creating Graphs for processes completed successfully")
    logging.info("Creating Graphs for CPU/RAM usage")
    for name in ('ram','cpu'):
        filename = global_csv_path + 'RestAPI_loop_' + name + '.csv'
        create_graph(filename, str(name),  name +'(%)','iterations',current_graph_folder,name)

def write_process_to_csv(i, process_name,process_vm):

    #csv_path = os.path.realpath(__file__) + os.sep + '..' + os.sep + os.path.join('csv')
    filename = global_csv_path + 'RestAPI_loop_' + str(process_name)+ '.csv'
    mode = 'a'
    if i == 0:
        mode = 'w'
    try:
        logging.debug("Trying to open " + filename + " to write data")
        with open(file=filename, mode=mode, newline='') as csvfile:
            fieldnames = ['iteration number', 'VMSize']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow({'iteration number': i, 'VMSize': process_vm})
    except Exception as ex:
        logging.error("exception while writing data into" + filename)
        csvfile.close()

def thread_manager(shells,ip, product_type, loops,time, username, password, private_key_path, certificate_path,fabric_health,graph_interval,recipient):
    logging.info("starting new thread: CPU/RAM Performance")
    t1 = threading.Thread(target=messurement_host_performance, args=(shells, loops))
    logging.info("Starting new thread: REST requests in loop")
    t2 = threading.Thread(target=run_rest_in_loop, args=(shells[2],ip, product_type, loops,time, username, password, private_key_path, certificate_path))
    logging.info("Measuring Processes virtual memory")
    #product_type = get_product_name_by_url(url)
    t3 = threading.Thread(target=virtual_memory_of_processes, args=(shells[3], loops, product_type))
    logging.info("Measuring Processes virtual memory")
    if str(fabric_health) == 'yes':
        t4 = threading.Thread(target=create_ufm_health_report, args=(ip, username, password))
        logging.info("Starting Fabric health Reports")
        t4.start()
    t5 = threading.Thread(target=graphs_scheduler, args=(graph_interval,product_type))
    logging.info("start Thread to for creating graphs every one hour")
    if recipient:
        t6 = threading.Thread(target=email_scheduler, args=(recipient, product_type, time,graph_interval))
        logging.info("sending emails with graphs every 24 hours")
        t6.start()


    t1.start()
    t2.start()
    t3.start()
    t5.start()


    t1.join()
    t2.join()
    t3.join()
    if str(fabric_health) == 'yes':
        t4.join()
    if recipient:
        t6.join()

    logging.info("Threads are joined!")
def send_neo_ports_rest_api(neo_ip):
    url = r'http://ip/neo/resources/ports?_=1543846564166&tz=Asia/Jerusalem'
    url = url.replace("ip", neo_ip)
    cookie = {"session":".eJyrVopPK0otzlCyKikqTdVRis9MUbKqVlJIUrJS8guJyooMSTeJrEqv8HdJyY4Mycj2D3et9HfJNvILycnwC3c1jQqPrIrK8rVVqgXqLUgtyk3MS80rgZlWWpxaBDZRKTElNzNPqRYAE_clcg.DubaoQ.I0UVeS061HEHVhzFeOqLobiNhTk"}
    payload = {"_":"1543846564166","tz":"Asia/Jerusalem"}
    logging.info("sending rest request for getting all ports ")
    try:
        r = requests.get(url= url, cookies=cookie, data=payload)
    except Exception as e:
        logging.error("exception when sending rest API to NEO for getting all ports" + str(e))
        return
    logging.info("Rest request for NEO succeeded.")
    return r
#(filename, str(process_name), 'VMSize(kb)','iterations',current_graph_folder,process_name )
def create_graph(filepath ,title, ylabel, xlabel, current_graph_folder, process_name):
    style.use('ggplot')
    #need to verify csv file is already exist
    if (os.path.isfile(filepath)) and (os.stat(filepath).st_size != 0):
        logging.debug("# File is exist : " + filepath)
        try:
            #C:\Users\arielwe\PycharmProjects\SecurityProject\Rest_Loop_CPU_RAM\csv\RestAPI_loop_mysqld.csv
            x,y = np.loadtxt(filepath, unpack=True,delimiter=',')
        except Exception as e:
            #TODO - debug
            print("Execption during creating geaphs/loadtext: " + str(e))
            print(e)
            print(filepath)
            print(process_name)
            print(current_graph_folder)
            print(ylabel)
            print(xlabel)
        try:
            plt.title(title)
            plt.ylabel(ylabel)
            plt.xlabel(xlabel)
            plt.plot(x,y)
            full_graph_path = current_graph_folder + process_name + ".png"
            plt.savefig(full_graph_path)
            plt.close()
        except Exception as ex:
            # TODO - debug
            print(traceback.format_exc())
            print("Exception in Create graphs")
            print(ex)
            print(filepath)
            print(process_name)
            print(current_graph_folder)
            print(ylabel)
            print(xlabel)
            print(x)
            print(y)
    else:
        logging.error("file is not exist : " + filepath )


def email_scheduler(recepint, product_type, time,graph_interval):
    sleep(60 + graph_interval)
    global stop,timer1
    if stop != False:
        timer1.cancel()
        return None
    else:
        timer1 = threading.Timer(graph_interval*60*60*24,email_scheduler,args=(recepint,product_type, time,graph_interval))
        timer1.start()
        send_email_to_recipient(recepint, product_type, time)

def graphs_scheduler(graph_interval,product_type):
    #TODO - Graphs are created only twices
    sleep(60)
    global stop, timer2
    if stop != False:
        timer2.cancel()
        return None
    else:
        if graph_interval:
            timer2 = threading.Timer(graph_interval*60 ,graphs_scheduler,args=(graph_interval,product_type))
            timer2.start()
        else:
            threading.Timer(3600, graphs_scheduler, args=(graph_interval,product_type)).start()
        logging.info("Creating Graphs #:  time is " +str(datetime.datetime.now()))
        create_graphs(product_type)

def get_payload_for_request(payload):
    with open(payload) as json_data:
        try:
            logging.debug("Parsing json payload from file...")
            json_obj = json.load(json_data)
        except Exception as ex:
            logging.error("Couldn't parse file to json object")
            sys.exit(1)
        logging.info("json file parsed successfully")
        json_data.close()
        return json_obj

def DisplayOptions():
    #TODO- fix useage
    usage = r"""usage: python memory_tester.py [options] arg1 arg2\n" 
    Examples: memory_tester.py  --product ufm -- ip 10.209.27.110 --time 48 --pkey alice.key  --certificate alice.cert.pem --graph_interval 60 &
              memory_tester.py --product neo --ip 10.209.26.75 --time 24 --graph_interval 6 --verbose debug --email arielwe@mellanox.com
              memory_tester.py --product ufmapl --ip 10.209.27.207 --time 1  --certificate alice.cert.pem --pkey alice.key  --graph_interval 6 --verbose debug --email arielwe@mellanox.com         
            """
    parser = optparse.OptionParser(usage=usage)
    parser.add_option("--product", dest="type", help="product type [ufm/ufmapl/neo]")
    parser.add_option("--ip", dest="ip", help="ip address of the machine")
    parser.add_option("--time", dest="time", help="total time for script to run in hours ")
    parser.add_option("--loops", dest="loops", help="number of REST calls in loop [Optional]")
    parser.add_option("--pkey", dest="private_key_path", help="private key path for SSL client certification [Optional]")
    parser.add_option("--certificate", dest="certificate_path", help="certificate path for SSL client certification [Optional]")
    parser.add_option("--fabric_health", dest="fabric_health", help="sending REST API calls to create UFM fabric health report [Optional]")
    parser.add_option("--graph_interval", dest="graph_interval", help=" create graphs every x minutes (default is '60') [Optional]")
    parser.add_option("--verbose", dest="verbose",help=" can be set as 'yes' for DEBUG verbosity (default is 'INFO') [Optional]")
    parser.add_option("--email", dest="receipient",help=" email address to send to result [Optional]")

    (options, args) = parser.parse_args()
    if ((options.type is None)  or (options.ip is None) or (options.time is None)):
        logging.error("Missing parameters for script...exiting\n")
        sys.exit(1)
    return options

def getIPfromURL(url):
    regex_url=r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    ip = findRegex(output=url,regex_search=regex_url)
    if not ip:
        logging.error("Couldn't retreived ip from URL")
        sys.exit(1)
    else:
        logging.debug("IP is: " + str(ip))
        return ip[0]

def get_username_password(credentials):
    splited = str(credentials).split(':')
    username, password = splited[0], splited[1]
    password.replace(':','')

    return username, password

def isShellMode(shell):
    cmd = '\n'
    expected = ['>']
    for cmd, expect in zip(cmd, expected):
        result, output = run_par_cmd(cmd=cmd, expect=expect, shell=shell)
        if ((int(result) == 0) and (len(output) > 0)):
            logging.debug(cmd + "working in Shell Mode equal true")
            return True
        else:
            logging.debug(cmd + "working in Shell Mode equal false")
            return False

def get_credentials_from_product_type(type):
    logging.info("Checking product type and set correct credentails")
    if type == 'ufm':
        logging.info("Product is UFM-IB")
        return ('admin','123456')
    elif type == 'neo':
        logging.info("Product is NEO")
        return ('admin','123456')
    elif type == 'ufmapl':
        logging.info("Product is UFM-Appliance")
        return ('admin','admin')

def main():
    options = DisplayOptions()
    type,ip, loops ,time, private_key_path,certificate_path, fabric_health, verbose, graph_interval, receipient= \
    options.type, options.ip ,options.loops, options.time, options.private_key_path, options.certificate_path, \
    options.fabric_health, options.verbose,options.graph_interval,options.receipient
    filename = 'memory_tester.log'

    if verbose:
        logging.basicConfig(filename=filename,
                            level=logging.DEBUG,
                            format='%(asctime)s %(levelname)-8s %(message)s',
                            datefmt='%m-%d %H:%M',
                            filemode='w')
    else:
        logging.basicConfig(filename=filename,
                            level=logging.INFO,
                            format='%(asctime)s %(levelname)-8s %(message)s',
                            datefmt='%m-%d %H:%M',
                            filemode='w')
    print("Script is running.......\nPlease check log file for more information:" + filename)
    logging.info("SCRIPT STARTS...............")
    logging.info("Graphs are located under " + global_graphs_path )
    creating_directory(global_csv_path)
    creating_directory(global_graphs_path)
    username, password = get_credentials_from_product_type(type)
    shells = []
    for i in range(5):
        if type == 'ufmapl':
            ssh = SSHConnect(ip=ip, username='admin', passowrd='admin')
        else:
            ssh = SSHConnect(ip=ip, username='root', passowrd='3tango')
        shells.append(createshell(ssh=ssh))
        if type == 'ufmapl':
            if isShellMode(shells[i]):
                ChangeToShellMode(shell=shells[i])
    thread_manager(shells,ip, type, loops,time, username, password, private_key_path, certificate_path,fabric_health,float(graph_interval),receipient)
    logging.info("Graphs are located under " + global_graphs_path )
    logging.info("Script is completed")
    print("Script is completed\n" + "Graphs are located under " + global_graphs_path )
    if receipient:
        send_email_to_recipient(receipient, type, time)
    print("Exit Script!\n")
    sys.exit()

if __name__ == '__main__':
    main()
