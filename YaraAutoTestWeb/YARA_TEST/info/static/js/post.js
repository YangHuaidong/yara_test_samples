function postfile(argument) {
  var filepath = $("#filepath").val();
  var samplestype = $("#select_samplestype option:selected").val();
  var datadict = {"filepath":filepath,"samplestype":samplestype};

  if (samplestype=="none")
  {
    if(confirm("请确认样本投放类型"))
    {
      $.ajax({
        url:'/post',
        data:datadict,
        type:"POST",
        // success : function(argument){
        //   alert("success");
        // },

        // error : function(argument){
        //   alert("error");
        // }
        });
      window.open("/getlog");
    }
  }
  if (samplestype=="black")  
  {
    if(confirm("当前样本投放类型为:黑样本"))
    {
      $.ajax({
        url:'/post',
        data:datadict,
        type:"POST",
        // success : function(argument){
        //   alert("success");
        // },

        // error : function(argument){
        //   alert("error");
        // }
        });
        window.open("/getlog");
    }
  }
  if (samplestype=="white")  
  {
    if(confirm("当前样本投放类型为:白样本"))
    {
      $.ajax({
        url:'/post',
        data:datadict,
        type:"POST",
        // success : function(argument){
        //   alert("success");
        // },

        // error : function(argument){
        //   alert("error");
        // }
        });
        window.open("/getlog");
    }
  }
}