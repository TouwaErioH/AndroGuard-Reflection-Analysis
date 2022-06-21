from androguard.misc import AnalyzeAPK
from androguard.decompiler.dad.decompile import DvMethod
from pprint import pprint
import re
import os

import time

'''
1.注意此项目中的androguard文件夹是 androguard的源码。使用pip安装到了c:/program1/anaconda/AndGrd1/sitepackages。所以想让修改生效，要么在本项目./androguard修改然后pip安装，要么直接修改sitepackages
    若只使用RefApIInfo.py统计反射api，不统计反射pattern，则无需修改AndroGuard源码，可以直接pip install .[magic,GUI]。
    甚至不需要从源码安装AndroGuard，直接pip install -U androguard[magic,GUI] 即可。
2.此脚本只统计 反射API调用情况，不统计反射pattern
'''

'''
问题
 1.ana.ref_api(clsname="Ljava/lang/Class", mtdname="getMethod") 匹配是正则匹配。 所以getmethod、getmethods都会被匹配到. 解决是 结尾加 '$'
 2. java forname本身就有两种形式 forName (Ljava/lang/String;) forName (Ljava/lang/String; Z Ljava/lang/ClassLoader;)。是否需要区分？  （感觉不用，因为返回值是一样的，只不过是static变量是否初始化的区别）
 3. 目前只统计了三个反射API
    ana.ref_api(clsname="Ljava/lang/Class", mtdname="forName$")
    ana.ref_api(clsname="Ljava/lang/Class", mtdname="getMethod$")
    ana.ref_api(clsname="Ljava/lang/reflect/Method", mtdname="invoke$")
    更多的API调用情况只需要根据method签名，调用ana.ref_api()。

    可以从TOSEM2021-Taming Reflection: An Essential Step Toward Whole-program Analysis of Android Apps  //droidra table1，table2  获取部分反射api；
    considering any call to a method implemented by the four reflection-related classes3 as a reflective call, except such methods that are overridden from java.lang.Object.
        java.lang.reflect.Field, java.lang.reflect.Method, java.lang.Class, and java.lang.reflect.Constructor.

 4.FLOWDROID resolves reflective calls only if their arguments are string constants, which is not always the case。
    后续可以统计有多少这种简单的反射调用
 5.关于反射pattern的识别，
    5.1.已放弃的方法可见refClass.py，采用的方法比较简单，先反编译method，逐行读取指令并切割出反射API和参数、返回值，根据经验判断；
    5.2 目前正在改用soot/flowdroid，根据icfg得到method调用流，从而总结反射pattern
'''

'''
test apps：
FINANCE:
    com.jingdong.app.mall.apk 127mb 
    com.taobao.taobao.apk 109MB
    com.tmall.wireless.apk 117
    com.amazon.mShop.android.shopping.apk  52.8mb
    com.aftership.AfterShip.apk 17MB

'''

class Refanaly:
    def __init__(self):
        self.ref_api_cnt = 0  # 总的反射次数
        self.ref_caller_method = []
        self.ref_caller_class = []  # 调用反射api的class
        self.called_ref_api = []  # 被调用的反射api

    def print_obj(obj):
        print(obj.__dict__)

    def ref_api(self, clsname='', mtdname=''):
        i = 1
        for MethodAnalyObj in dx.find_methods(classname=clsname, methodname=mtdname):
            # print_obj(MethodAnalyObj)
            # MethodAnalyObj.show()
            print("reflection API:", MethodAnalyObj.method.name)   #被调用的反射API
            print("reflection API class:", MethodAnalyObj.method.class_name) #被调用的反射API所属Class
            print("reflection API dex", MethodAnalyObj.get_vm()) #被调用的反射API所属dex ；因为是系统api，所以不存在；

            if MethodAnalyObj.method.full_name not in self.called_ref_api:
                self.called_ref_api.append(MethodAnalyObj.method.full_name)

            for xm in MethodAnalyObj.get_xref_from():
                # if xm[0].is_external():
                #    continue
                # if "Landroid/support" in xm[1].method.full_name.decode("utf-8"):
                #    continue
                # if "Landroidx" in xm[1].method.full_name.decode("utf-8"):
                #    continue
                # if "Lkotlin" in xm[1].method.full_name.decode("utf-8"):
                #    continue
                self.ref_api_cnt = self.ref_api_cnt + 1
                print("xref count：", i)       #该反射API第几次被调用
                i = i + 1
                # MethodAnalyObj.show()
                print("xref method:", xm[1].method.name) #调用该反射API的method
                print("xref offset(byte)", xm[2])  #调用该反射API的指令（instruction）在method内部的偏移。单位为byte
                print("xref method full name:", xm[1].method.full_name)
                print("xref class:", xm[1].method.class_name) #调用该反射API的method所属Class
                print("xref dex", xm[1].get_vm()) #调用该反射API的method所属dex
                instrus = xm[1].get_method().get_instructions_idx();
                for idx, ins in instrus:
                    if idx == xm[2]:
                        print("xref code:", idx, ins.get_op_value(), ins.get_name(), ins.get_output()) #调用该反射API的指令（instruction）
                        break

                if xm[1].method.full_name not in self.ref_caller_method:
                    self.ref_caller_method.append(xm[1].method.full_name)
                if xm[1].method.class_name not in self.ref_caller_class:
                    self.ref_caller_class.append(xm[1].method.class_name)


        print("end")


if __name__ == '__main__':
    print("androguard init started")
    time_start = time.time()

    a, d, dx = AnalyzeAPK("./testapps/shopping/com.aftership.AfterShip.apk")
    # a, d, dx = AnalyzeAPK("./testapps/shopping/com.amazon.mShop.android.shopping.apk")
    # a, d, dx = AnalyzeAPK("./testapps/shopping/com.tmall.wireless.apk")
    # a, d, dx = AnalyzeAPK("./testapps/shopping/com.jingdong.app.mall.apk")
    # a, d, dx = AnalyzeAPK("./testapps/shopping/com.taobao.taobao.apk")
    # a, d, dx = AnalyzeAPK("./testapps/ref3-staticArray.apk")

    time_end = time.time()
    time_sum = time_end - time_start
    print("androguard init finished %s s" % (time_sum))
    time_start = time.time()

    ana = Refanaly()

    # reflection api
    ana.ref_api(clsname="Ljava/lang/Class", mtdname="forName$")
    ana.ref_api(clsname="Ljava/lang/Class", mtdname="getMethod$")
    ana.ref_api(clsname="Ljava/lang/reflect/Method", mtdname="invoke$")



    time_end = time.time()
    time_sum = time_end - time_start
    print("androguard analysis finished %s s" % (time_sum))

    print("总的反射调用次数：", ana.ref_api_cnt)
    print("调用了反射API的method的数量", len(ana.ref_caller_method))
    print("调用了反射API的Class的数量", len(ana.ref_caller_class))
    print("被调用的反射api有多少类：", len(ana.called_ref_api))
    print(ana.called_ref_api)
    print("apk总的classes数量", len(dx.get_classes()))
    print("apk总的methods数量", len(list(dx.get_methods())))
    print("projectfinished")


