# coding:utf-8
from lib.core.option import *
import os


if __name__ == '__main__':
    version = 'v0.1'
    progam = u'''
  _______      _______.  ______      ___      .__   __. 
 /  _____|    /       | /      |    /   \     |  \ |  |    {version:%s}
|  |  __     |   (----`|  ,----'   /  ^  \    |   \|  | 
|  | |_ |     \   \    |  |       /  /_\  \   |  . `  |    
|  |__| | .----)   |   |  `----. /  _____  \  |  |\   | 
 \______| |_______/     \______|/__/     \__\ |__| \__|    
                                                        
    
    ''' % version
    print(progam)

    main(os.path.dirname(os.path.abspath(__file__)))
