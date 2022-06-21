
from androguard.misc import AnalyzeAPK
from androguard.decompiler.dad.decompile import DvMethod
from pprint import pprint
import re
import os

import time

'''
1.注意此项目中的androguard文件夹是 androguard的源码。使用pip安装到了c:/program1/anaconda/AndGrd1/sitepackages。所以想让修改生效，要么在本项目./androguard修改然后pip安装，要么直接修改sitepackages
2.此脚本统计 反射API调用情况，以及反射pattern。采用的方法比较简单，先反编译method，逐行读取指令并切割出反射API和参数、返回值，根据经验判断； 
    目前已经弃用。正在改用soot/flowdroid，根据icfg得到method调用流，从而总结反射pattern
'''

'''
问题
 1.ana.ref_api(clsname="Ljava/lang/Class", mtdname="getMethod") 匹配是正则匹配。 所以getmethod、getmethods都会被匹配到. 解决是 结尾$
 2. java forname本身就有两种形式 forName (Ljava/lang/String;) forName (Ljava/lang/String; Z Ljava/lang/ClassLoader;)。是否需要区分？  （感觉不用，因为返回值是一样的，只不过是static变量是否初始化的区别）
 3. 目前只统计了Class.forname1->getmethod->invoke 这一个pattern（forname的两种实现都统计了）。
    其他pattern、api都没统计，所以#{'forname1info': [], 'getmethodinfo': [], 'invokeinfo': [(17, 'v2_2', '            return ((String) v2_2.invoke(0, v3_1));')]}  这种他肯定也是有pattern的，只是没有统计。
 4.根据 line ->str 切割反射的结果、参数肯定是不够准确的，所以后续打算改成根据AST
 5.FLOWDROID resolves reflective calls only if their arguments are string constants, which is not always the case。
    可以统计有多少这种简单的反射调用

修改源码：
 1.修改了getsource。返回str
 2.修改了dad graph，不log Multiple exit nodes found

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
        self.refinfo = {} #从反编译代码，转str，然后切出来的反射信息
        self.astrefinfo={} #从ast中获取的反射信息
        self.failed_decompile=[] #反编译调用了反射api的method时，失败的次数
        self.Multiple_exit_decompile=[]
        self.ref_api_cnt=0 #总的反射次数
        self.cross_method_ref=0   #跨method进行反射的数量.比如getmethod、forname的反射结果不是作为局部变量，而是作为参数。 更准确的说是：pattern不在method内部的数量。 也不太准确，比如invoke就没有关心结果是否作为了参数
        self.ref_caller_method=[]
        self.ref_caller_class=[] #调用反射api的class
        self.called_ref_api=[] #被调用的反射api

    def print_obj(obj):
        print(obj.__dict__)

    def ref_api(self,clsname='',mtdname=''):
        i = 1
        for MethodAnalyObj in dx.find_methods(classname=clsname,methodname=mtdname):
            #print_obj(MethodAnalyObj)
            #MethodAnalyObj.show()
            print("reflection API:", MethodAnalyObj.method.name)
            print("reflection API class:",MethodAnalyObj.method.class_name)
            print("reflection API dex",MethodAnalyObj.get_vm())

            if MethodAnalyObj.method.full_name not in self.called_ref_api:
                self.called_ref_api.append(MethodAnalyObj.method.full_name)

            for xm in MethodAnalyObj.get_xref_from():
                #if xm[0].is_external():
                #    continue
                #if "Landroid/support" in xm[1].method.full_name.decode("utf-8"):
                #    continue
                #if "Landroidx" in xm[1].method.full_name.decode("utf-8"):
                #    continue
                #if "Lkotlin" in xm[1].method.full_name.decode("utf-8"):
                #    continue
                self.ref_api_cnt=self.ref_api_cnt+1
                print("xref count：",i)
                i = i + 1
                #MethodAnalyObj.show()
                print("xref method:", xm[1].method.name)
                print("xref offset(byte)", xm[2])
                print("xref method full name:", xm[1].method.full_name)
                print("xref class:",xm[1].method.class_name)
                print("xref dex",xm[1].get_vm())
                instrus=xm[1].get_method().get_instructions_idx();
                for idx, ins in instrus:
                    if idx==xm[2]:
                        print("xref code:",idx, ins.get_op_value(), ins.get_name(), ins.get_output())
                        break

                if xm[1].method.full_name not in self.ref_caller_method:
                    self.ref_caller_method.append(xm[1].method.full_name)
                if xm[1].method.class_name not in self.ref_caller_class:
                    self.ref_caller_class.append(xm[1].method.class_name)

                #以下是用反编译的代码，切割每一行代码，来判断pattern; 目前只有Class.forname1->getmethod->invoke 这一个pattern
                #decompile             # 根据DECOMPILE line->str，汇总method内部所有的反射api信息
                if xm[1].is_external():
                    continue
                if xm[1].method.full_name in self.refinfo:
                    print("exist")
                    continue
                try:
                    decompilecode=xm[1].get_method().source() #  可能会遇到问题：  Multiple exit nodes found !  这是dad反编译的问题；androguard不会中断运行，但是不一定正确。
                except:
                    print("decompile failed:" ,xm[1].method.full_name)   #除了Multiple exit nodes found 还有别的反编译问题。 会中断运行，就必须跳过
                    self.failed_decompile.append(xm[1].method.full_name)
                    continue
                splitdecompile=decompilecode.split('\n')

                forname1info=[]
                getmethodinfo=[]
                invokeinfo=[]
                idx=0
                for line in splitdecompile:
                    idx=idx+1
                    if ".forName(" in line: #= Class.forName(
                        print(line)
                        if "=" not in line:
                            self.cross_method_ref=self.cross_method_ref+1
                            continue
                        va=line.split("=")[0].split(" ")[-2]  #等号前面的变量。即Class.forName创建的 class object v2_1// Class v2_1 = Class.forName(de.ecspride.ReflectiveClass);
                        forname1info.append((idx,va,line))


                    '''
                    跑京东的时候遇到一个case 
                    int v0_4 = v1_0.getMethod(put, v3_6);
                    reflect.Method v6_1 = v1_0.getMethod(get, v3_7);
                    v1_1(v0_4, v6_1, v1_0.getMethod(remove, v3_8), v8, v9);
                    见语雀
                    '''
                    if ".getMethod(" in line:
                        print(line)
                        if "=" not in line: #作为参数，即跨method
                            self.cross_method_ref = self.cross_method_ref + 1
                            continue
                        va1 = line.split("=")[0].split(" ")[-2] #等号前面的变量。即getmethod创建的 method object v4_1 //reflect.Method v4_1 = v2_1.getMethod(setImei, v6_0);
                        va2 = line.split("=")[1].split(".getMethod")[0][1:]  # .getmethod的参数，即所属class //v2_1
                        getmethodinfo.append((idx,va1,va2,line))
                    if ".invoke(" in line:
                        print(line)
                        va = line.split(".invoke")[0].split(" ")[-1]  #INVOKE的method，即v4_1  // v4_1.invoke(v3, v6_1);
                        invokeinfo.append((idx,va,line))
                self.refinfo[xm[1].method.full_name]={"forname1info":forname1info,"getmethodinfo":getmethodinfo,"invokeinfo":invokeinfo}


                #ast
                if xm[0].is_external():
                    continue
                if xm[1].method.full_name in self.astrefinfo:
                    print("exist")
                    continue
                #dv = DvMethod(xm[1])
                #dv.process(doAST=True)
                #ast1=dv.get_ast()
                #locate_ast(ast1["body"],mtdname,clsname)
                #pprint(dv.get_ast())



        print("end")


    def locate_ast(astb):
        #todo
        return

if __name__ == '__main__':
    print("androguard init started")
    time_start = time.time()

    a, d, dx = AnalyzeAPK("./testapps/shopping/com.aftership.AfterShip.apk")
    #a, d, dx = AnalyzeAPK("./testapps/shopping/com.amazon.mShop.android.shopping.apk")
    #a, d, dx = AnalyzeAPK("./testapps/shopping/com.tmall.wireless.apk")
    #a, d, dx = AnalyzeAPK("./testapps/shopping/com.jingdong.app.mall.apk")
    #a, d, dx = AnalyzeAPK("./testapps/shopping/com.taobao.taobao.apk")
    #a, d, dx = AnalyzeAPK("./testapps/ref3-staticArray.apk")


    time_end = time.time()
    time_sum = time_end - time_start
    print("androguard init finished %s s"%(time_sum))
    time_start = time.time()

    ana = Refanaly()

    #pattern 1： Class.forName() → getMethod() → invoke()
    ana.ref_api(clsname="Ljava/lang/Class",mtdname="forName$")
    ana.ref_api(clsname="Ljava/lang/Class", mtdname="getMethod$")
    ana.ref_api(clsname="Ljava/lang/reflect/Method", mtdname="invoke$")

    #根据DECOMPILE line->str，汇总的method内部所有的反射api信息，判断pattern。 只能判断method内部的反射
    #print(ana.refinfo)
    inner_pattern=0
    for key in ana.refinfo:
        #print("method name：",key)
        #Class.forname1->getmethod->invoke
        for i in ana.refinfo[key]["forname1info"]:
            classobj=i[1];
            for j in ana.refinfo[key]["getmethodinfo"]:
                if j[2]==i[1]:
                    for k in ana.refinfo[key]["invokeinfo"]:
                        if k[1]==j[1]:
                            print("method name：",key)
                            print("Class.forname1->getmethod->invoke:%s->%s->%s"%(i[2],j[3],k[2]))
                            inner_pattern=inner_pattern+1

    time_end = time.time()
    time_sum = time_end - time_start
    print("androguard analysis finished %s s"%(time_sum))

    print("failed_decompile method cnt:",len(ana.failed_decompile))
    print("总的反射调用次数：",ana.ref_api_cnt)
    print("method内反射pattern(Class.forname->getmethod->invoke)的数量：", inner_pattern)
    print("非method内的反射调用:",ana.cross_method_ref)
    print("ref_caller_method cnt",len(ana.ref_caller_method))
    print("ref_caller_class cnt",len(ana.ref_caller_class))
    print("被调用的反射api数量：",len(ana.called_ref_api))
    print(ana.called_ref_api)
    print("classes in apk",len(dx.get_classes()))
    print("methods in apk",len(list(dx.get_methods())))
    print("projectfinished")
'''
问题
 1.ana.ref_api(clsname="Ljava/lang/Class", mtdname="getMethod") 匹配是正则匹配。 所以getmethod、getmethods都会被匹配到. 解决是 结尾$
 2. java forname本身就有两种形式 forName (Ljava/lang/String;) forName (Ljava/lang/String; Z Ljava/lang/ClassLoader;)。是否需要区分？  （感觉不用，因为返回值是一样的，只不过是static变量是否初始化的区别）
 3. 目前只统计了Class.forname1->getmethod->invoke 这一个pattern（forname的两种实现都统计了）。
    其他pattern、api都没统计，所以#{'forname1info': [], 'getmethodinfo': [], 'invokeinfo': [(17, 'v2_2', '            return ((String) v2_2.invoke(0, v3_1));')]}  这种他肯定也是有pattern的，只是没有统计。
 4.根据 line ->str 切割反射的结果、参数肯定是不够准确的，所以后续打算改成根据AST
 5.FLOWDROID resolves reflective calls only if their arguments are string constants, which is not always the case。
    可以统计有多少这种简单的反射调用

修改源码：
 1.修改了getsource。返回str
 2.修改了dad graph，不log Multiple exit nodes found

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

