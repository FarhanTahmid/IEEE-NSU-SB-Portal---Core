/*
Template Name: Symox - Admin & Dashboard Template
Author: Themesbrand
Website: https://Themesbrand.com/
Contact: Themesbrand@gmail.com
File: dashboard Analytics Init Js File
*/

function getChartColorsArray(chartId) {
    if (document.getElementById(chartId) !== null) {
        var colors = document.getElementById(chartId).getAttribute("data-colors");
        colors = JSON.parse(colors);
        return colors.map(function (value) {
            var newValue = value.replace(" ", "");
            if (newValue.indexOf("--") != -1) {
                var color = getComputedStyle(document.documentElement).getPropertyValue(
                    newValue
                );
                if (color) return color;
            } else {
                return newValue;
            }
        });
    }
}
async function fetchData2() {
  try {
      const response = await fetch('/users/get_dashboard_mini_chart1_stats/?event_stat=' + encodeURIComponent('event_number'));
      const data = await response.json();
      return data;
  } catch (error) {
      console.error('Error fetching data:', error);
      throw error; // Rethrow the error for further handling
  }
}
// mini-1
async function initializeMiniChart1() {
  try {
var barchartColors = getChartColorsArray("mini-1");
var options = {
    series: [{
      data: []
    }],
    chart: {
      type: 'line',
      height: 61,
      sparkline: {
        enabled: true
      }  
    },
    colors: barchartColors,
    stroke: {
      curve: 'smooth',
      width: 2.5,
    },
    tooltip: {
      fixed: {
        enabled: false
      },
      x: {
        show: false
      },
      y: {
        title: {
          formatter: function (seriesName) {
            return ''
          }
        }
      },
      marker: {
        show: false
      }
    }
  };
      const data = await fetchData2();
      options.x = Object.keys(data);
      options.series[0].data = Object.values(data);
      console.log(data)
  var chart = new ApexCharts(document.querySelector("#mini-1"), options);
chart.render();
} catch (error) {
  
}
}

initializeMiniChart1();

// mini-2
var barchartColors = getChartColorsArray("mini-2");
var options = {
    series: [{
      data: [36, 12, 30, 20, 36, 14]
    }],
    chart: {
      type: 'line',
      height: 61,
      sparkline: {
        enabled: true
      }  
    },
    colors: barchartColors,
    stroke: {
      curve: 'smooth',
      width: 2.5,
    },
    tooltip: {
      fixed: {
        enabled: false
      },
      x: {
        show: false
      },
      y: {
        title: {
          formatter: function (seriesName) {
            return ''
          }
        }
      },
      marker: {
        show: false
      }
    }
  };

  var chart = new ApexCharts(document.querySelector("#mini-2"), options);
chart.render();


// mini-3
var barchartColors = getChartColorsArray("mini-3");
var options = {
    series: [{
      data: [14, 40, 14, 46, 28, 38]
    }],
    chart: {
      type: 'line',
      height: 61,
      sparkline: {
        enabled: true
      }  
    },
    colors: barchartColors,
    stroke: {
      curve: 'smooth',
      width: 2.5,
    },
    tooltip: {
      fixed: {
        enabled: false
      },
      x: {
        show: false
      },
      y: {
        title: {
          formatter: function (seriesName) {
            return ''
          }
        }
      },
      marker: {
        show: false
      }
    }
  };

  var chart = new ApexCharts(document.querySelector("#mini-3"), options);
chart.render();


// mini-4
var barchartColors = getChartColorsArray("mini-4");
var options = {
    series: [{
      data: [34, 2, 30, 12, 35, 20]
    }],
    chart: {
      type: 'line',
      height: 61,
      sparkline: {
        enabled: true
      }  
    },
    colors: barchartColors,
    stroke: {
      curve: 'smooth',
      width: 2.5,
    },
    tooltip: {
      fixed: {
        enabled: false
      },
      x: {
        show: false
      },
      y: {
        title: {
          formatter: function (seriesName) {
            return ''
          }
        }
      },
      marker: {
        show: false
      }
    }
  };

  var chart = new ApexCharts(document.querySelector("#mini-4"), options);
chart.render();



//  Sales Statistics
// Function to fetch data from Django API
async function fetchData() {
  try {
      const response = await fetch('/users/get_dashboard_stats/?stat_type=' + encodeURIComponent('recruitment_stat'));
      const data = await response.json();
      return data;
  } catch (error) {
      console.error('Error fetching data:', error);
      throw error; // Rethrow the error for further handling
  }
}

// Asynchronous function to initialize the chart
async function initializeChart() {
  try {
      var barchartColors = getChartColorsArray("recruitment-statistics");

      var options = {
          series: [{
              data: []
          }],
          chart: {
              toolbar: {
                  show: false,
              },
              height: 350,
              type: 'bar',
              events: {
                  click: function (chart, w, e) {
                      // Handle click event if needed
                  }
              }
          },
          plotOptions: {
              bar: {
                  columnWidth: '70%',
                  distributed: true,
              }
          },
          dataLabels: {
              enabled: false
          },
          legend: {
              show: false
          },
          colors: barchartColors,
          xaxis: {
              categories: [], // Categories will be populated dynamically
              labels: {
                  style: {
                      colors: barchartColors,
                      fontSize: '12px'
                  }
              }
          }
      };

      // Fetch data and update chart options
      const data = await fetchData();
      options.xaxis.categories = Object.keys(data);
      options.series[0].data = Object.values(data);
      console.log(data)
      // Create and render the chart
      var chart = new ApexCharts(document.querySelector("#recruitment-statistics"), options);
      chart.render();
  } catch (error) {
      console.error('Error initializing chart:', error);
  }
}

// Call the asynchronous function to initialize the chart
initializeChart();



// Sales Category

var barchartColors = getChartColorsArray("earning-item");
var options = {
    series: [
    {
      data: [
        {
          x: 'Iphone',
          y: [
            new Date('2021-10-02').getTime(),
                  new Date('2021-10-10').getTime()
          ],
          fillColor: barchartColors[0]
        },
        {
            x: 'Android',
            y: [
                new Date('2021-10-12').getTime(),
                new Date('2021-10-21').getTime()
            ],
            fillColor: barchartColors[1]
        },
        {
          x: 'Watch 8',
          y: [
            new Date('2021-10-06').getTime(),
            new Date('2021-10-16').getTime()
          ],
          fillColor: barchartColors[0]
        },
        {
          x: 'Books',
          y: [
            new Date('2021-10-12').getTime(),
                  new Date('2021-10-22').getTime()
          ],
          fillColor: barchartColors[1]
        },
        {
          x: 'Speaker',
          y: [
            new Date('2021-10-05').getTime(),
            new Date('2021-10-16').getTime()
          ],
          fillColor: barchartColors[0]
        },
        {
          x: 'Cover',
          y: [
            new Date('2021-10-17').getTime(),
            new Date('2021-10-26').getTime()
          ],
          fillColor: barchartColors[1]
        }
      ]
    }
  ],
    chart: {
    height: 398,
    type: 'rangeBar',
    toolbar: {
        show: false
    }
  },
  plotOptions: {
    bar: {
      horizontal: true,
      barHeight: '30%',
    }
  },
  xaxis: {
    type: 'datetime'
  }
  };

  var chart = new ApexCharts(document.querySelector("#earning-item"), options);
  chart.render();

  // Sales Category
  
  Chart.pluginService.register({
    afterUpdate: function (chart) {
      for (var i = 1; i < chart.config.data.labels.length; i++) {
        var arc = chart.getDatasetMeta(0).data[i];
        arc.round = {
          x: (chart.chartArea.left + chart.chartArea.right) / 2,
          y: (chart.chartArea.top + chart.chartArea.bottom) / 2,
          radius: (chart.outerRadius + chart.innerRadius) / 2,
          thickness: (chart.outerRadius - chart.innerRadius) / 2 - 1,
          backgroundColor: arc._model.backgroundColor
        }
      }
      // Draw rounded corners for first item
      var arc = chart.getDatasetMeta(0).data[0];
      arc.round = {
        x: (chart.chartArea.left + chart.chartArea.right) / 2,
        y: (chart.chartArea.top + chart.chartArea.bottom) / 2,
        radius: (chart.outerRadius + chart.innerRadius) / 2,
        thickness: (chart.outerRadius - chart.innerRadius) / 2 - 1,
        backgroundColor: arc._model.backgroundColor
      }
    },
  
    afterDraw: function (chart) {
      for (var i = 1; i < chart.config.data.labels.length; i++) {
        var ctx = chart.chart.ctx;
        arc = chart.getDatasetMeta(0).data[i];
        var startAngle = Math.PI / 2 - arc._view.startAngle;
        var endAngle = Math.PI / 2 - arc._view.endAngle;
        ctx.save();
        ctx.translate(arc.round.x, arc.round.y);
        ctx.fillStyle = arc.round.backgroundColor;
        ctx.beginPath();
        ctx.arc(arc.round.radius * Math.sin(endAngle), arc.round.radius * Math.cos(endAngle), arc.round.thickness, 0, 2 * Math.PI);
        ctx.closePath();
        ctx.fill();
        ctx.restore();
      }
      // Draw rounded corners for first item
      var ctx = chart.chart.ctx;
      arc = chart.getDatasetMeta(0).data[0];
      var startAngle = Math.PI / 2 - arc._view.startAngle;
      var endAngle = Math.PI / 2 - arc._view.endAngle;
      ctx.save();
      ctx.translate(arc.round.x, arc.round.y);
      ctx.fillStyle = arc.round.backgroundColor;
      ctx.beginPath();
      // ctx.arc(arc.round.radius * Math.sin(startAngle), arc.round.radius * Math.cos(startAngle), arc.round.thickness, 0, 2 * Math.PI);
      ctx.arc(arc.round.radius * Math.sin(endAngle), arc.round.radius * Math.cos(endAngle), arc.round.thickness, 0, 2 * Math.PI);
      ctx.closePath();
      ctx.fill();
      ctx.restore();
    },
  });

  async function fetchData3() {
    try {
        const response = await fetch('/users/get_dashboard_event_type_stats/?event_stat=' + encodeURIComponent('event_number'));
        const data = await response.json();
        return data;
    } catch (error) {
        console.error('Error fetching data:', error);
        throw error; // Rethrow the error for further handling
    }
  }
  // round corners
  async function initializePieChart() {
    try {
  var salescategorycolors = getChartColorsArray('sales-category');
  var config = {
    type: 'doughnut',
    data: {
      labels: ['Watch', 'Iphone', 'Book', 'TV'],
      datasets: [{
        data: [35, 20, 8, 7, 10],
        backgroundColor: salescategorycolors,
        hoverBackgroundColor: salescategorycolors,
        borderWidth: 0,
        borderColor: salescategorycolors,
        hoverBorderWidth: 0,
      }]
    },
    options: {
      responsive: false,
      legend: {
        display: false //This will do the task
      },
      tooltips: {
        enabled: true,
      },
      cutoutPercentage: 75,
      rotation: -0.5 * Math.PI,
      circumference: 2 * Math.PI,
      title: {
        display: false
      },
    }
  };
  
  var ctx = document.getElementById('sales-category');
  
  window.myDoughnut = new Chart(ctx, config);
    const data = await fetchData3();
      
      console.log(data)
  // window.myDoughnut.generateLegend();
} catch (error) {
  console.error('Error initializing chart:', error);
}
}
