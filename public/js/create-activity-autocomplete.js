var requestedAttendees = [];
var choices = users.map(x => { return x.properties.firstName + ' ' + x.properties.lastName });
new autoComplete({
    selector: 'input[name="requestedAttendees"]',
    minChars: 1,
    source: function(term, suggest){
        var choices = users.map(x => { return x.properties.firstName + ' ' + x.properties.lastName; });
        var matches = [];
        term = term.toLowerCase();
        term_array = term.split(',');
        requestedAttendees = document.getElementById('requestedAttendees').value.split(',');
        requestedAttendees.pop();
        term = term_array[term_array.length - 1].trim();
        for (i=0; i<choices.length; i++)
            {if (~choices[i].toLowerCase().indexOf(term)) { matches.push(choices[i]); }}
        suggest(matches);
    },
    renderItem: function (item, search) {
        return '<div class="autocomplete-suggestion" name-value="' + item + '">' + item + '</div>'
    },
    onSelect: function(e, term, item) {
        index = choices.indexOf(item.getAttribute('name-value'));
        requestedAttendees.push(users[index].properties.email);
        document.getElementById('requestedAttendees').value = requestedAttendees.join(', ');
    }
});
