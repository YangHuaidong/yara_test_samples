function reanalysis(id) {

    var reanalysisurl = '/reanalysis/' + id
    if (confirm("是否确认重新解析?")) {
        var d = document.getElementById(id);
        d.innerHTML = "正在重新解析...";
        d.setAttribute("disabled", true);
        d.className = "a-btn ban";

        $.ajax({
            url: reanalysisurl,
            type: "POST",
            success: function (id) {
                d.innerHTML = "重新解析"
                // d.setAttribute("onclick","reanalysis(this.id)");
                location.reload();
                d.className = "a-btn";
            },

            // error : function(argument){
            //   alert("error");
            // }
        });
    }

}

function reanalysisall(id) {
    var reanalysisurl = '/reanalysis/' + id

    if (confirm("是否确认全部重新解析?")) {
        var d = document.getElementById(id);
        d.value = "正在全部重解析...";
        d.setAttribute("disabled", true);

        $.ajax({
            url: reanalysisurl,
            type: "POST",
            success: function (id) {
                d.innerHTML = "一键全部重解析"
                // d.setAttribute("onclick","reanalysis(this.id)");
                location.reload();
            },

            // error : function(argument){
            //   alert("error");
            // }
        });
    }

}