function searchfunction(){
    let input,filter,table,tr,td,j;
    input=document.getElementById("search");
    filter=input.value.toUpperCase();
    table=document.getElementById("recruitee_table");
    tr=table.getElementsByTagName("tr");
    
    for(j=0;j<tr.length;j++){
        td=tr[j].getElementsByTagName("td");
        message=document.getElementById("no_data");

        if(td.length > 0){
            if(td[0].innerHTML.toLocaleUpperCase().indexOf(filter)> -1 ||
            td[1].innerHTML.toLocaleUpperCase().indexOf(filter)> -1 ||
            td[2].innerHTML.toLocaleUpperCase().indexOf(filter)> -1 ||
            td[3].innerHTML.toLocaleUpperCase().indexOf(filter)> -1 ||
            td[4].innerHTML.toLocaleUpperCase().indexOf(filter)> -1 ||
            td[5].innerHTML.toLocaleUpperCase().indexOf(filter)> -1 ||
            td[6].innerHTML.toLocaleUpperCase().indexOf(filter)> -1){
            tr[j].style.display="";
            message.innerHTML="";
        }
                else{
                    tr[j].style.display="none";
                }
        
        }        
        if(td.length==0){
            message.innerHTML="Member not found!";
        }
    }
}