"""
@Author: J. Alexander
@Date: 7/9/2017
@Version: 1.0

Program Purpose: This is a variation of the other MFTCleaner.py. I'm writing this program
to learn how to write APIs. 

This program should probably be split up so that it sends the CSV to the server before 
filtering it. The only problem is that the CSV is too big to send as a whole over HTTP 
without breaking it up first. 

Maybe we can use the client machine to do the initial filtering and then have the server 
program run a variation of sentiment analysis on the filtered program. 

EXAMPLE USAGE: ~$ python CleanMFT.py /User/glassCodeBender/Documents/mft_csv.csv username
"""""

import pandas as pd
import re
import sys
import os
from requests import put, get
import datetime

class CleanMFT:
    def __init__(self, id = sys.argv(1), import_file = sys.argv(2), reg_file=True, output_filename = os.getcwd() + "result.csv",
                 suspicious=False, start_date='', end_date='', start_time='', end_time='', filter_index = ''):
        self.__file = import_file       # stores the FQDN of the MFT CSV file
        self.__id = id                  # this value will be used as the id at the end of the URL.
        self.__reg_file = reg_file      # accepts a txt file
        self.__suspicious = suspicious
        self.__start_date = start_date  # accepts a date to filter
        self.__end_date = end_date
        self.__start_time = start_time  # accepts a time to filter
        self.__end_time = end_time
        self.__output_file = output_filename
        self.__filter_index = filter_index

    """ This is the main method of the program. """
    def run(self):
        sdate, edate, stime, etime = self.__start_date, self.__end_date, self.__start_time, self.__end_time
        output_file = self.__output_file
        suspicious = self.__suspicious
        mft_csv = self.__file
        reg_file = self.__reg_file
        id = self.__id

        sindex, eindex = [x.strip() for x in self.__filter_index.split(',')]
        if sindex.contains(',') or eindex.contains(','):
            sindex.replace(',', '')
            eindex.replace(',', '')
        if not sindex.isdigit and eindex.isdigit:
            raise ValueError("ERROR: The index value you entered to filter the table by was improperly formatted. \n"
                             "Please try to run the program again with different values.")
        df = pd.DataFrame()
        df = df.from_csv(mft_csv, sep='|', parse_dates=[[0, 1]])
        # df = df.from_csv("MftDump_2015-10-29_01-27-48.csv", sep='|')
        # df_attack_date = df[df.index == '2013-12-03'] # Creates an extra df for the sake of reference
        df = df.reset_index(level=0, inplace=True)
            if sindex and eindex:
                df = df[sindex : eindex]
        if reg_file:
            df = self.filter_by_filename(df)
        if suspicious:
            df = self.filter_suspicious(df)
        if sdate or edate or stime or etime:
            df = self.filter_by_dates(df)
        filtered_df = df.to_csv(index=True) # To make this easier, we'll send the CSV String as JSON field.
        address = 'http://localhost:5000/' + id
        put(address, {'data': filtered_df}).json() # send a put request using requests library.


    """ 
    Read a file line by line and return a list with items in each line.
    @Param A Filename
    @Return A list 
    """
    def read_file(self, file):
        list = []
        with open(file) as f:
            for line in f:
                list.append(line)
        return list

    """ 
    Method to filter a list of words and concatenate them into a regex
    @Param List of words provided by user to alternative file.
    @Return String that will be concatenated to a regex. 
    """
    def update_reg(self, list):
        s = '|'
        new_reg = s.join(list)
        return new_reg

    """ 
    Filters a MFT csv file that was converted into a DataFrame to only include relevant extensions.
    @Param: DataFrame 
    @Return: DataFrame - Filtered to only include relevant file extensions. 
    """
    def filter_by_filename(self, df):
        reg_file = self.__reg_file
        reg_list = self.read_file(reg_file)
        user_reg = self.update_reg(reg_list)

        if user_reg is not None:
            pattern = r'' + user_reg
        else:
            pattern = r'.exe|.dll|.rar|.sys|.jar'

        regex1 = re.compile(pattern, flags=re.IGNORECASE)
        df['mask'] = df[['Filename', 'Desc']].apply(lambda x: x.str.contains(regex1, regex=True)).any(axis=1)
        filt_df = df[df['mask'] == True]

        pattern2 = r'Create$|Entry$'
        regex2 = re.compile(pattern2, flags=re.IGNORECASE)
        filt_df['mask2'] = filt_df[['Type']].apply(lambda x: x.str.contains(regex2, regex=True)).any(axis=1)
        filtered_df = filt_df[filt_df['mask2'] == True]
        filtered_df.drop(['mask', 'mask2'], axis=1, inplace=True)

        return filtered_df

    """ 
    Filters a MFT so that only the executables that were run outside Program Files are 
    included in the table. 
    @Param: DataFrame 
    @Return: DataFrame - Filtered to only include relevant file extensions. 
    """
    def filter_suspicious(self, df):
        pattern = r'^.+(Program\sFiles|System32).+[.exe]$'
        regex1 = re.compile(pattern)
        df['mask'] = df[['Filename', 'Desc']].apply(lambda x: x.str.contains(regex1, regex=True)).any(axis=1)
        filt_df = df[df['mask'] == False]

        pattern2 = r'.exe$'
        regex2 = re.compile(pattern2)
        filt_df['mask2'] = filt_df[['Filename', 'Desc']].apply(lambda x: x.str.contains(regex2, regex=True)).any(axis=1)
        filtered_df = filt_df[filt_df['mask2'] == True]
        filtered_df.drop(['mask', 'mask2'], axis=1, inplace=True)
        return filtered_df

    """ 
    Filters a MFT csv file that was converted into a Dataframe to only include the 
    occurrences of certain dates and/or times.
    @Param: DataFrame 
    @Return: DataFrame - Filtered to only include relevant virus names. 
    """
    def filter_by_dates(self, df):

        sdate = self.__start_date
        edate = self.__end_date
        stime = self.__start_time
        etime = self.__end_time

        if edate and sdate and etime and stime:
            s_stamp = pd.Timestamp(sdate + ' ' + stime)
            e_stamp = pd.Timestamp(edate + ' ' + etime)
            filtered_df = df[s_stamp:e_stamp]
        elif sdate and edate and etime and not stime:
            s_stamp = pd.Timestamp(sdate)
            e_stamp = pd.Timestamp(edate + ' ' + etime)
            filtered_df = df[s_stamp:e_stamp]
        elif sdate and edate and stime:
            s_stamp = pd.Timestamp(sdate + ' ' + stime)
            e_stamp = pd.Timestamp(edate)
            filtered_df = df[s_stamp:e_stamp]
        elif sdate and stime:
            s_stamp = pd.Timestamp(sdate + ' ' + stime)
            filtered_df = df[s_stamp:]
        elif edate and etime:
            e_stamp = pd.Timestamp(edate + ' ' + etime)
            filtered_df = df[:e_stamp]
        elif sdate:
            s_stamp = pd.Timestamp(sdate)
            filtered_df = df[s_stamp:]
        elif edate:
            e_stamp = pd.Timestamp(edate)
            filtered_df = df[:e_stamp]
        else:
            raise ValueError("You entered an invalid date to filter the table by or you did not include a date\n")
        return filtered_df
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("An error occurred when you started the program. You must enter both a username and filename.")
        sys.exit(1)
    mft = CleanMFT(id = sys.argv(1), import_file = sys.argv(2))
    mft.run
