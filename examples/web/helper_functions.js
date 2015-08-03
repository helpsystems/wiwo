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

/* It adds to the DOM the references of a pie chart from a pie chart's data structure. */
function create_references_for_pie_chart(_chart_id, _data) 
{
    var _chart_pie_ref = document.getElementById(_chart_id);
    while (_chart_pie_ref.firstChild) {
        _chart_pie_ref.removeChild(_chart_pie_ref.firstChild);
    }

    for (var i = 0; i < _data.length; i++) {
        var _span = document.createElement("span");
        var _color = document.createTextNode("\u00a0\u00a0\u00a0");
        _span.appendChild(_color);
        _span.style.backgroundColor = _data[i].color;
        
        var _div = document.createElement("div");
        var _ref = "\u00a0" + _data[i].label + ": " + _data[i].value;
        var _text = document.createTextNode(_ref);
        
        _div.appendChild(_span);
        _div.appendChild(_text);
        _chart_pie_ref.appendChild(_div);
    }
}    

/* It adds to the DOM the references of a chart (other than pie chart) from the right data structure. */
function create_references(_chart_id, _data) 
{

    var _chart = document.getElementById(_chart_id);
    while (_chart.firstChild) {
        _chart.removeChild(_chart.firstChild);
    }

    for (var i = 0; i < _data.labels.length; i++) {
        for (var j = 0; j < _data.datasets.length; j++) {
            var _span = document.createElement("span");
            var _color = document.createTextNode("\u00a0\u00a0\u00a0");
            _span.appendChild(_color);
            _span.style.backgroundColor = _data.datasets[j].fillColor;
        
            var _div = document.createElement("div");
            var _ref = "\u00a0" + _data.labels[i] + ": " + _data.datasets[j].data[i];
            var _text = document.createTextNode(_ref);
            
            _div.appendChild(_span);
            _div.appendChild(_text);
            _chart.appendChild(_div);
        }
    }
}

/* It returns a color in hex from a color array. */
function get_color(i) {
    colors = ["#B39EB5", "#77DD77", "#FF6961", "#779ECB", "#FFB347", "#CFCFC4", "#F49AC2", "#AEC6CF", "#FDFD96", "#C23B22", "#71BC78", "#0095B6", "#B19CD9", "#DEA5A4", "#FFD1DC", "#03C03C", "#CB99C9", "#836953", "#966FD6", "#E5B73B", "#87A96B", "#CD5B45", "#E9D66B", "#555555", "#CB4154", "#960018", "#4D5D53", "#D68A59", "#C2B280", "#0087BD"]
    
    while (i >= colors.length)
        i = i - colors.length;
        
    return colors[i]
}

/* It returns a pie chart's segment. */
function pieChartSegment(label, value, idx) {
    color = get_color(idx);
    
    return {
          "value": value,
          "color": color,
          "label": label
    }
}

/* It transforms the data from server format ( [ [label1, label2], [ [value1], [value2] ] ] )
 to a pie chart segment objects' array. */
function updateDataToPieData(data) {
    var ret = [];
    for (var i = 0; i < data[0].length; i++) {
        var label = data[0][i];
        var value = data[1][i][0];
        ret.push(pieChartSegment(label, value, i));  
    }      
    
    return ret;
}

/* It returns a chart data set object. */
function chartDataSet(label, value, idx) {
    color = get_color(idx);
    
    return {
            label: label,
            fillColor: color,
            data: value
    }
}

/* It transforms the data from server format ( [ [label1, label2], [ [value1A, value1B], [value2A, value2B] ] ] )
 to a chart data set objects' array. */   
function updateDataToChartData(data) {
    var ret = {
        labels: data[0],
        datasets: []
    };
    
    var sets = [];
    
    for (var i = 0; i < data[1].length; i++) {
        values = data[1][i];
        for (var j = 0; j < values.length; j++) {
            if (i == 0)
                sets.push([])
            sets[j].push(values[j])
        }
    }    
    
    for (var k = 0; k < sets.length; k++)
        ret.datasets.push(chartDataSet("", sets[k], k));
    
    return ret;
}
