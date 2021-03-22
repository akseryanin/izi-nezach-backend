$(document).ready(function () {
    let marksTable = $('#marks')
        .DataTable({
            paging: false,
            lengthChange: false,
            searching: false,
            ordering: false,
            scrollX: true,
            fixedColumns: {
                leftColumns: 1,
            }
        })
        .on('edit', 'tbody td', function () {
            console.log('value by API : ', this.parentNode.rowIndex, this.cellIndex, this.textContent);
        });

    $(".mycell")
        .inputFilter(function (value) {
            // return ["1", "2", "3", "4", "5", "Н", "н", "у", "У", "п", "П", ""].includes(value);
            return ["1", "2", "3", "4", "5", ""].includes(value);
        })
        .change(function () {
            let val = val_from_cell_name(this.name);
            let x = get_x_key(val.x_index);
            let y = get_y_key(val.y_key_id);
            let markVal = this.value;
            let m = make_mark(x, y, subject_id, val.mark_id, markVal);

            console.log("made mark", m);
            axios.post('/api/marks/add', m).then((response) => {
                let data = response.data;
                // console.log('fff',data.error);

                if (data.error !== undefined) {
                    alert(data.error);
                    location.reload();
                    return;
                }

                if (val.mark_id === '') {
                    console.log("mark created, id=", data.id);
                    val.mark_id = '' + data.id;
                    this.name = val_to_string(val);
                } else {
                    if (this.value === '') {
                        val.mark_id = '';
                        this.name = val_to_string(val);
                        // console.log("mark deleted")
                    } else {
                        // console.log("mark exists");
                    }
                }
                console.log(data);
            });
        });

    function get_x_key(x_index) {
        return x_keys[-1 + x_index]
    }

    function get_y_key(y_key_id) {
        return y_keys.filter(y => (y.id === y_key_id))[0]
    }

    function make_mark(x, y, subject_id, mark_id, val) {
        if (mark_id === '') {
            mark_id = null;
        } else {
            mark_id = parseInt(mark_id, 10);
        }
        return {
            lesson_id: '' + x.val,
            student_id: '' + y.val,
            subject_id: subject_id,
            mark_id: mark_id,
            value: val,
        }
    }

    function val_from_cell_name(name) {
        let s = ('' + name).replace(/'/g, '"');
        s = JSON.parse(s);
        return {
            x_index: s.x_index,
            y_key_id: s.y_key_id,
            mark_id: s.mark_id,
        }
    }

    function val_to_string(val) {
        return JSON.stringify(val).replace(/"/g, "'")
    }
});
