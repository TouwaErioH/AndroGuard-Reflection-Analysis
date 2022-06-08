# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.

from androguard.misc import AnalyzeAPK
import re
def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
    print(f'Hi, {name}')  # Press Ctrl+F8 to toggle the breakpoint.




def print_obj(obj):
    print(obj.__dict__)

def search_method(apkobj,class_name, name, descriptor, re_expr=True):
    l = []
    if re_expr == True:
        ex = re.compile(class_name)

        for m, _ in apkobj.get_packages_names():
            if ex.match(m.get_info()) != None:
                l.extend(m.search_method(name, descriptor))

    return l


def getcodeee():
    #raw bytecode
    for method in dx.get_methods():
        if method.is_external():
            continue
        m = method.get_method()
        if m.get_code():
            print(m.get_code().get_bc().get_raw())
    #instructions
    for method in dx.get_methods():
        if method.is_external():
            continue
        m = method.get_method()
        for idx, ins in m.get_instructions_idx():
            print(idx, ins.get_op_value(), ins.get_name(), ins.get_output())

    #instructions by method
    for m in dx.find_methods("Ljava/lang/reflect/Method/invoke;"):
        print(m.full_name)
        if m.is_external():
            continue
        for idx, ins in m.get_method().get_instructions_idx():
            print(idx, ins.get_op_value(), ins.get_name(), ins.get_output())

    #source code（decompile）
    for method in dx.get_methods():
        if method.is_external():
            continue
        m = method.get_method()
        print(m.source())


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    print("androguard init started")
    #a, d, dx = AnalyzeAPK("./testapps/com.jingdong.app.mall.apk")
    a, d, dx = AnalyzeAPK("./testapps/ref3-staticArray.apk")
    print(d)
    print("androguard init finished")

    dis1=d[0].disassemble(0x447ec,236)

    #invoke是系统调用，externalmethod。所以也没有对应的dvm（dex），None
    for m in dx.find_methods(classname="Ljava/lang/reflect/Method",methodname="invoke"):
        print(m.full_name)
        if m.is_external():
            print("is external")
            continue
        print(m.get_vm())
        for idx, ins in m.get_method().get_instructions_idx():
            print(idx, ins.get_op_value(), ins.get_name(), ins.get_output())

    #reflection3的一个内部method。  但是注意onCreateOptionsMenu也被识别了。
    for m in dx.find_methods(classname=r'.*'+"/MainActivity", methodname="onCreate"):
        print(m.full_name)
        if m.is_external():
            print("is external")
            continue
        print(m.get_vm())
        dvm1=m.get_vm()
        #dvm1.show()
        print(m.get_method().source())
        for idx, ins in m.get_method().get_instructions_idx():
            print(idx, ins.get_op_value(), ins.get_name(), ins.get_output())


    #name1=d[0].create_python_export()
    i=1
    for MethodAnalyObj in dx.find_methods(classname="Ljava/lang/reflect/Method",methodname="invoke"):      #java.lang.reflect.Method.invoke()
        print(i)
        print_obj(MethodAnalyObj)
        #MethodAnalyObj.show()
        #print(MethodAnalyObj.method.class_name)
        print(MethodAnalyObj.get_vm())
        i=i+1
        for xm in MethodAnalyObj.get_xref_from():
            if xm[0].is_external():
                continue
            print(xm)
    print("projectfinished")
# See PyCharm help at https://www.jetbrains.com/help/pycharm/

'''



  -o, --offset INTEGER  Offset to start dissassembly inside the file
  -s, --size INTEGER    Number of bytes from offset to disassemble, 0 for
                        whole file

思路：
1.目前调用method已经可以找到所属class了。即定位了反射调用mthod
    然后后面可以看pattern，根据xreffrom、to
2.看看参数能不能解，明文字符串这种。 算是数据引用？
3.
      class method string field都有index，具体可以看androguard的文档

4.  关于这个偏移具体是怎么算的、怎么反编译的，再看看
知识：
1. <analysis.MethodAnalysis Lde/ecspride/MainActivity;->onCreate(Landroid/os/Bundle;) Lde/ecspride/MainActivity;是smali的class的格式
2.想恢复dex的名字classes2.dex这种是没有意义的。因为是jadx命名的规则，androguard是按照地址（dvm object）区分dex。可以根据包含的class来判断和jadx的对应关系。

问题：
1.已知method，怎么找所属dex  。  get_vm()
2.xref返回值：
    是list of tuple
    比如一个tuple(<analysis.ClassAnalysis Lde/ecspride/MainActivity;>, <analysis.MethodAnalysis Lde/ecspride/MainActivity;->onCreate(Landroid/os/Bundle;)V [access_flags=protected] @ 0x447ec>, 222)
    @ 0x447ec:
        debug看oncreate的methodanalysis object，0x447ec是280,556，code是<androguard.core.bytecodes.dvm.DalvikCode object at 0x0000025FD89D9EB0>的code offset：280556。即oncreate在dex中的偏移、、
    222:
            for idx, ins in m.get_method().get_instructions_idx():
            print(idx, ins.get_op_value(), ins.get_name(), ins.get_output())
            这么打印一看222是invoke-static、invoke-virtual的idx （在method oncreate内部的偏移）

      
'''