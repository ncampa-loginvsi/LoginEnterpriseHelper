# Login Enterprise

This repository contains useful commands and scripts for use with Login Enterprise public API. 

## AccountManagement.ps1 

This file can be used to edit account passwords after creating them in bulk. You might have accounts LoginEnt0001, ..., LoginEnt1000. Because bulk creation does not currently allow for unique passwords, it may seem tidious to manually edit each account, certainly as the number of accounts increases. 

The script takes a ```pathToCSV``` as an argument, which must be in the following format. 

| Username    | Password            |
| ----------- | ------------------- |
| User1       | User1Password       |
| User2       | User2Password       |

Algorithm:
* Import the CSV file
* For each Username in the CSV:
   * Query account information for the Username account
   * Configure the Username account to use Username's password as defined in CSV
