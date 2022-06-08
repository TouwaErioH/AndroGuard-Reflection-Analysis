def is_reflection_code(dx) :
    """
        Reflection is present ?
        :param dx : the analysis virtual machine
        :type dx: a :class:`VMAnalysis` object
        :rtype: boolean
    """
    paths = dx.get_tainted_packages().search_methods( "Ljava/lang/reflect/Method;", ".", ".")
    if paths != [] :
        return True

    return False

    def search_methods(self, class_name, name, descriptor, re_expr=True):
        """
            @param class_name : a regexp for the class name of the method (the package)
            @param name : a regexp for the name of the method
            @param descriptor : a regexp for the descriptor of the method
            @rtype : a list of called methods' paths
        """
        #for m, _ in self.get_packages():
        #    #print m.get_paths()
        #    for i in m.get_methods():
        #        print i.get_descriptor()
        #        print i.get_class_name()

        #print "search"
        l = []
        if re_expr == True:
            ex = re.compile(class_name)

            for m, _ in self.get_packages():
                if ex.match(m.get_info()) != None:
                    l.extend(m.search_method(name, descriptor))

        return l

    def get_packages(self):
        for i in self.__packages:
            yield self.__packages[i], i

    def search_method(self, name, descriptor):
        """
            @param name : a regexp for the name of the method
            @param descriptor : a regexp for the descriptor of the method
            @rtype : a list of called paths
        """
        #print "search_method"
        l = []
        m_name = re.compile(name)
        m_descriptor = re.compile(descriptor)

        for path in self.paths[TAINTED_PACKAGE_CALL]:
            if m_name.match(path.get_name()) != None and m_descriptor.match(path.get_descriptor()) != None:
                l.append(path)
        return l
