/*
-*- coding: iso-8859-15 -*-

Copyright 2003-2015 CORE Security Technologies

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Authors:
         Andres Blanco (6e726d)
         Andres Gazzoli
*/

function loadCharts() {

    $.ajax({
   	url: "api/frames_per_channel",
        success: function(data_str) {
            var data_json = JSON.parse(data_str);
            var pieData = updateDataToPieData(data_json);
      	    
            var ctx = document.getElementById("frames_per_channel_chart-area").getContext("2d");
            var myPieChart = new Chart(ctx).Pie(pieData);

            create_references_for_pie_chart("frames_per_channel_chart-area-ref", pieData);
   	    }
    }); 

    $.ajax({
   	url: "api/data_qos_data_frames_per_channel",
        success: function(data_str) {
            var data_json = JSON.parse(data_str);
            var data = updateDataToChartData(data_json);
                
            var ctx = document.getElementById("data_qos_data_frames_per_channel_chart-bar").getContext("2d");
            var myBarChart = new Chart(ctx).Bar(data);

            create_references("data_qos_data_frames_per_channel_chart-bar-ref", data);
   	    }
    }); 

    $.ajax({
   	url: "api/traffic_encryption",
        success: function(data_str) {
            var data_json = JSON.parse(data_str);
            var pieData = updateDataToPieData(data_json);
        
            var ctx = document.getElementById("traffic_encryption_chart-area").getContext("2d");
            var myPieChart = new Chart(ctx).Pie(pieData);

            create_references_for_pie_chart("traffic_encryption_chart-area-ref", pieData);
   	    }
    }); 

    $.ajax({
   	url: "api/access_points_per_channel",
        success: function(data_str) {
            var data_json = JSON.parse(data_str);
            var data = updateDataToChartData(data_json);
        
            var ctx = document.getElementById("access_points_per_channel_chart-bar").getContext("2d");
            var myBarChart = new Chart(ctx).Bar(data);
            
            create_references("access_points_per_channel_chart-bar-ref", data);
   	    }
    });   

    
    // Reload charts.
    setTimeout(function() {
        loadCharts();
    }, 5000);
}
