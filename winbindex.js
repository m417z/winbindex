/* global BootstrapDialog, yadcf, Q, pako */

var globalFunctions = {};

(function () {
    'use strict';

    animateLogo();

    globalFunctions.onHashCopyClick = onHashCopyClick;
    globalFunctions.onShowExtraClick = onShowExtraClick;

    var displayFile = getParameterByName('file');
    if (displayFile) {
        if (/(^\.\.[/\\]|^\/etc\/)/.test(displayFile)) {
            location = 'https://www.youtube.com/watch?v=sTSA_sWGM44';
            return;
        }

        displayFile = displayFile.replace(/[<>:"/\|?*]/g, '');
    }

    if (displayFile) {
        var newTitle = displayFile + ' - Winbindex';
        $('#main-title').text(newTitle);
        document.title = newTitle;

        var searchQuery = getParameterByName('search');

        loadFileInfoToTable(displayFile, searchQuery);
    } else {
        loadFileNames();
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    // Based on: https://codepen.io/riazxrazor/pen/Gjomdp
    function animateLogo() {
        var canvas = document.getElementById('main-logo-canvas');
        var ctx = canvas.getContext('2d');
        var charArr = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'];
        var fallingCharArr = [];
        var fontSize = 8;
        var ch = canvas.getBoundingClientRect().height;
        var cw = canvas.getBoundingClientRect().width;
        var maxColums = cw / fontSize;

        canvas.width = cw;
        canvas.height = ch;

        function randomInt(min, max) {
            return Math.floor(Math.random() * (max - min) + min);
        }

        function randomFloat(min, max) {
            return Math.random() * (max - min) + min;
        }

        function Point(x, y) {
            this.x = x;
            this.y = y;
            this.speed = randomFloat(2, 5);
        }

        Point.prototype.draw = function (ctx) {
            this.value = charArr[randomInt(0, charArr.length - 1)].toUpperCase();

            ctx.fillStyle = '#0F0';
            ctx.font = fontSize + 'px san-serif';
            ctx.fillText(this.value, this.x, this.y);

            this.y += this.speed;
            if (this.y > ch) {
                this.y = randomFloat(-100, 0);
                this.speed = randomFloat(2, 5);
            }
        };

        for (var i = 0; i < maxColums; i++) {
            fallingCharArr.push(new Point(i * fontSize, randomFloat(-500, 0)));
        }

        var animationOn = false;
        var frameDelay = 0;
        var animationFramePending = false;
        var frameCount = 0;
        var update = function () {
            ctx.fillStyle = 'rgba(0,0,0,0.05)';
            ctx.fillRect(0, 0, cw, ch);

            var i = fallingCharArr.length;

            while (i--) {
                fallingCharArr[i].draw(ctx);
            }

            frameCount++;
            if (frameCount < 100 || animationOn) {
                frameDelay = 0;
            } else {
                frameDelay += 10;
            }

            if (frameDelay < 100) {
                animationFramePending = true;
                if (frameDelay > 0) {
                    setTimeout(function () {
                        requestAnimationFrame(update);
                    }, frameDelay);
                } else {
                    requestAnimationFrame(update);
                }
            } else {
                animationFramePending = false;
            }
        };

        canvas.parentNode.onmouseover = function () {
            animationOn = true;
            if (!animationFramePending) {
                update();
            }
        };

        canvas.parentNode.onmouseout = function () {
            animationOn = false;
        };

        update();
    }

    function loadFileNames() {
        // select2 is 2 slow!
        /*$('#winbindex-file-select').select2({
            placeholder: 'Select a file',
            allowClear: true,
            data: data
        });*/

        var DataProvider = function () {
            this.availableItems = null;
            this.items = null;
        };
        DataProvider.prototype.load = function () {
            var deferred = Q.defer();
            var self = this;
            if (this.availableItems) {
                deferred.resolve();
            } else {
                $.ajax({
                    url: 'data/filenames.json'
                }).done(function (data) {
                    self.availableItems = [];
                    data.forEach(function (item) {
                        self.availableItems.push({
                            id: item,
                            name: item
                        });
                    });
                    self.items = self.availableItems;

                    // Prevent filckering with setTimeout.
                    setTimeout(function () {
                        $('#winbindex-file-select-container').removeClass('d-none');
                        $('#page-loader').hide();
                    }, 0);

                    deferred.resolve();
                }).fail(function (jqXHR, textStatus, errorThrown) {
                    var msg = textStatus;
                    if (errorThrown) {
                        msg += ': ' + errorThrown;
                    }
                    alert(msg);
                });
            }
            return deferred.promise;
        };
        DataProvider.prototype.filter = function (search) {
            var searchArray = search.toLowerCase().split(/\s+/);
            if (searchArray.length > 0) {
                this.items = this.availableItems.filter(function (item) {
                    return searchArray.every(function (word) {
                        return item.name.indexOf(word) !== -1;
                    });
                });
            } else {
                this.items = this.availableItems;
            }
        };
        DataProvider.prototype.get = function (firstItem, lastItem) {
            return this.items.slice(firstItem, lastItem);
        };
        DataProvider.prototype.size = function () {
            return this.items.length;
        };
        DataProvider.prototype.identity = function (item) {
            return item.id;
        };
        DataProvider.prototype.displayText = function (item, extended) {
            if (item) {
                return item.name;
                //return extended ? item.name + ' (' + item.id + ')' : item.name;
            } else {
                return '';
            }
        };
        DataProvider.prototype.noSelectionText = function () {
            return 'Select a file';
        };
        var dataProvider = new DataProvider();

        $('#winbindex-file-select').virtualselect({
            dataProvider: dataProvider,
            onSelect: function (item) {
                $('#winbindex-file-value').val(item.id);
                $('#winbindex-file-select-container button[type=submit]').removeAttr('disabled');
            },
        }).virtualselect('load');
    }

    function loadFileInfoToTable(fileToLoad, searchQuery) {
        var filesTable = $('#winbindex-table').DataTable({
            responsive: true,
            deferRender: true,
            stateSave: true,
            fnStateLoadParams: function (oSettings, oData) {
                delete oData.columns;
                oData.search.search = searchQuery || '';
            },
            oSearch: {
                sSearch: searchQuery || ''
            },
            columnDefs: [
                {
                    targets: 'target-hash',
                    width: '1%',
                    sortable: false,
                    render: function (data, type) {
                        if (!/^[a-fA-F0-9]+$/.test(data)) {
                            return '???';
                        }

                        if (type !== 'display') {
                            return data;
                        }

                        var textLimit = 6;
                        var textShown = data.slice(0, textLimit);
                        //var textHidden = data.slice(textLimit);

                        var seeMoreLink = $('<a data-toggle="tooltip" data-html="true" href="#"></a>')
                            .text(textShown + '…')
                            .prop('title', escapeHtml(data) + '<br><br>Click to copy')
                            .attr('onclick', 'arguments[0].stopPropagation(); return globalFunctions.onHashCopyClick(this, "' + data + '");');

                        return seeMoreLink[0].outerHTML;
                    }
                }, {
                    targets: 'target-array-of-values',
                    width: '18%',
                    render: function (data, type) {
                        if (type !== 'display') {
                            return escapeHtmlAsUnicodeLookalike(data.sort || data.title);
                        }

                        if (data.items.length === 1 && data.items[0] === data.title) {
                            return escapeHtml(data.title);
                        }

                        var itemsToShow = data.items;
                        if (itemsToShow.length > 10) {
                            itemsToShow = itemsToShow.slice(0, 5).concat(['(' + (itemsToShow.length - 10)  + ' more items)']).concat(itemsToShow.slice(-5));
                        }

                        var titleSuffix = '';
                        if (data.items.length > 1) {
                            titleSuffix = ' (+' + (data.items.length - 1) + ')';
                        }

                        var element = $('<abbr data-toggle="tooltip" data-html="true"></abbr>')
                            .text(data.title + titleSuffix)
                            .prop('title', itemsToShow.map(escapeHtml).join('<br>'));

                        return element[0].outerHTML;
                    }
                }, {
                    targets: 'target-file-arch',
                    render: function (data, type) {
                        if (!data) {
                            return '???';
                        }

                        var text = humanFileArch(data);

                        if (type !== 'display') {
                            return escapeHtmlAsUnicodeLookalike(text);
                        }

                        return escapeHtml(text);
                    }
                }, {
                    targets: 'target-file-version',
                    render: function (data, type) {
                        if (!data) {
                            return '???';
                        }

                        var text = data.split(' ', 2)[0];

                        if (type !== 'display') {
                            return escapeHtmlAsUnicodeLookalike(text);
                        }

                        return escapeHtml(text);
                    }
                }, {
                    targets: 'target-file-size',
                    searchable: false,
                    render: function (data, type) {
                        if (type !== 'display') {
                            return data !== null ? data : -1;
                        }

                        if (!data) {
                            return '???';
                        }

                        return escapeHtml(humanFileSize(data));
                    }
                }, {
                    targets: 'target-file-signing-date',
                    render: function (data, type) {
                        if (!data || data.length === 0) {
                            return '???';
                        }

                        var text = data[0].slice(0, '2000-01-01'.length);

                        if (type !== 'display') {
                            return escapeHtmlAsUnicodeLookalike(text);
                        }

                        return escapeHtml(text);
                    }
                }, {
                    targets: 'target-extra-button',
                    className: 'text-center',
                    width: '1%',
                    searchable: false,
                    sortable: false,
                    render: function (data) {
                        var element = $('<a href="#" class="btn btn-secondary btn-sm">Show</a>')
                            .attr('onclick', 'arguments[0].stopPropagation(); return globalFunctions.onShowExtraClick(this, "' + data.hash + '", "' + encodeURIComponent(JSON.stringify(data.data, null, 4)) + '");');

                        return element[0].outerHTML;
                    }
                }, {
                    targets: 'target-download-button',
                    className: 'text-center',
                    width: '1%',
                    searchable: false,
                    sortable: false,
                    render: function (data) {
                        if (!data.timestamp || !data.virtualSize) {
                            if (/\.(exe|dll|sys)$/.test(displayFile)) {
                                var msg = 'Download is not available since the file isn\'t available on VirusTotal';
                            } else {
                                var msg = 'Download is only available for executables such as exe, dll, and sys files';
                            }
                            return '<span class="disabled-cursor" data-toggle="tooltip" title="' + msg + '">' +
                                '<a href="#" class="btn btn-secondary btn-sm disabled">Download</a></span>';
                        }

                        // "%s/%s/%08X%x/%s" % (serverName, peName, timeStamp, imageSize, peName)
                        // https://randomascii.wordpress.com/2013/03/09/symbols-the-microsoft-way/

                        var fileName = displayFile;
                        var fileId = ('0000000' + data.timestamp.toString(16).toUpperCase()).slice(-8) + data.virtualSize.toString(16).toLowerCase();
                        var url = 'https://msdl.microsoft.com/download/symbols/' + fileName + '/' + fileId + '/' + fileName;

                        var element = $('<a class="btn btn-secondary btn-sm">Download</a>')
                            .prop('href', url).attr('onclick', 'arguments[0].stopPropagation();');

                        return element[0].outerHTML;
                    }
                }, {
                    targets: 'target-plain-text',
                    render: function (data, type) {
                        if (!data) {
                            return '???';
                        }

                        if (type !== 'display') {
                            return escapeHtmlAsUnicodeLookalike(data);
                        }

                        return escapeHtml(data);
                    }
                }
            ],
            order: [[$('#winbindex-table thead th.order-default-sort').index(), 'desc']],
            preDrawCallback: function (settings) {
                this.find('[data-toggle="tooltip"]').tooltip('dispose');
            }
        });
        $('#winbindex-table').tooltip({selector: '[data-toggle=tooltip]'});

        var yadcfColumnOptions = {
            filter_reset_button_text: false,
            filter_match_mode: 'exact',
            column_data_type: 'rendered_html',
            select_type: 'select2',
            select_type_options: {
                theme: 'bootstrap4',
                language: 'he',
                dropdownAutoWidth: true
            }
        };
        var yadcfColumns = [];
        $('#winbindex-table thead th .winbindex-column-header-with-yadcf').each(function () {
            var columnHeader = $(this);
            var columnNumber = columnHeader.parent().index();
            var filterDefaultLabel = columnHeader.text();
            var options = $.extend({
                column_number: columnNumber,
                filter_default_label: filterDefaultLabel
            }, yadcfColumnOptions);

            if (columnHeader.hasClass('winbindex-yadcf-multiple')) {
                options.text_data_delimiter = ',';
                delete options.filter_match_mode; // otherwise it won't match
            }

            yadcfColumns.push(options);
        });

        yadcf.init(filesTable, yadcfColumns);

        initHiddenColumns(filesTable);

        filesTable.responsive.recalc();

        $.ajax({
            url: 'data/by_filename_compressed/' + displayFile + '.json.gz',
            // https://stackoverflow.com/a/17682424
            xhrFields: {
                responseType: 'blob'
            }
        }).done(function (compressed) {
            var fileReader = new FileReader();
            fileReader.onload = function (event) {
                var arrayBuffer = event.target.result;

                var data = JSON.parse(pako.ungzip(arrayBuffer, { to: 'string' }));

                var mainDescription = '';
                var mainDescriptionUpdate = '';

                var rows = [];
                Object.keys(data).forEach(function (hash) {
                    var d = data[hash];

                    var fileInfo = d.fileInfo || {};
                    var sha1 = fileInfo.sha1 || null;
                    var md5 = fileInfo.md5 || null;
                    var description = fileInfo.description || null;
                    var machineType = fileInfo.machineType || null;
                    var signingDate = fileInfo.signingDate || null;
                    var size = fileInfo.size || null;
                    var version = fileInfo.version || null;

                    var assemblyArchitecture = getAssemblyParam(d, 'processorArchitecture');
                    var assemblyVersion = getAssemblyParam(d, 'version');

                    var win10Versions = getWin10Versions(d);
                    var updateKbs = getUpdateKbs(d);

                    rows.push([
                        hash,
                        sha1,
                        md5,
                        win10Versions,
                        updateKbs,
                        machineType,
                        version,
                        size,
                        signingDate,
                        assemblyArchitecture,
                        assemblyVersion,
                        { hash: hash, data: d },
                        fileInfo
                    ]);

                    if (description && updateKbs.items[0] && updateKbs.items[0] > mainDescriptionUpdate) {
                        mainDescription = description;
                        mainDescriptionUpdate = updateKbs.items[0];
                    }
                });
                $('#winbindex-table-container').removeClass('winbindex-table-container-hidden');
                filesTable.rows.add(rows).draw();
                $('#page-loader').hide();

                $('#main-description').text(mainDescription);
            };
            fileReader.readAsArrayBuffer(compressed);
        }).fail(function (jqXHR, textStatus, errorThrown) {
            var msg = textStatus;
            if (errorThrown) {
                msg += ': ' + errorThrown;
            }
            alert(msg);
        });
    }

    function initHiddenColumns(table) {
        var hiddenColumns = null;
        try {
            hiddenColumns = localStorage.getItem('winbindex-hidden-columns');
        } catch (e) { }

        if (!hiddenColumns) {
            hiddenColumns = [];
            $('#winbindex-table thead th.hidden-by-default').each(function () {
                hiddenColumns.push($(this).index());
            });
        }

        hiddenColumns.forEach(function (columnIndex) {
            table.column(columnIndex).visible(false);
        });

        var settingsButton = $('#winbindex-settings-button');
        $('#winbindex-table_filter').append(settingsButton);

        settingsButton.find('.dropdown-menu .dropdown-item-column').each(function (columnIndex) {
            if (hiddenColumns.indexOf(columnIndex) === -1) {
                $(this).find('input[type="checkbox"]').prop('checked', true);
            }

            $(this).click(function () {
                toggleHiddenColumn(this, table, columnIndex);
                return false;
            });
        });
    }

    function toggleHiddenColumn(element, table, columnIndex) {
        var checkbox = $(element).find('input[type="checkbox"]');
        var checked = checkbox.prop('checked');
        table.column(columnIndex).visible(!checked);
        checkbox.prop('checked', !checked);
    }

    function getAssemblyParam(data, param) {
        var values = {};

        var windowsVersions = data.windowsVersions;
        Object.keys(windowsVersions).forEach(function (windowsVersion) {
            Object.keys(windowsVersions[windowsVersion]).forEach(function (update) {
                if (update !== 'BASE') {
                    var assemblies = windowsVersions[windowsVersion][update].assemblies;
                    Object.keys(assemblies).forEach(function (assembly) {
                        var paramValue = assemblies[assembly].assemblyIdentity[param];
                        if (paramValue) {
                            values[paramValue] = true;
                        }
                    });
                }
            });
        });

        values = Object.keys(values);
        if (values.length === 1) {
            return values[0];
        }

        return null;
    }

    function getWin10Versions(data) {
        var items = Object.keys(data.windowsVersions).map(function (item) {
            return 'Windows 10 ' + item;
        });

        items.sort();

        var title = items[0] || '-';

        return {
            items: items,
            title: title,
            sort: items.join(',') || title
        };
    }

    function getUpdateKbs(data) {
        var items = [];

        var windowsVersions = data.windowsVersions;
        Object.keys(windowsVersions).forEach(function (windowsVersion) {
            Object.keys(windowsVersions[windowsVersion]).forEach(function (update) {
                if (update === 'BASE') {
                    var windowsVersionInfo = windowsVersions[windowsVersion][update].windowsVersionInfo;
                    var date = windowsVersionInfo.releaseDate;
                    var itemText = date + ' - Base ' + windowsVersion;
                    items.push(itemText);
                } else {
                    var updateInfo = windowsVersions[windowsVersion][update].updateInfo;
                    var date = updateInfo.releaseDate.slice(0, '2000-01-01'.length);
                    var itemText = date + ' - ' + updateInfo.updateKb;
                    items.push(itemText);
                }
            });
        });

        items.sort();

        var title = '-';
        if (items.length > 0) {
            title = items[0].slice('2000-01-01 - '.length);
        }

        return {
            items: items,
            title: title,
            sort: items.join(',') || title
        };
    }

    // https://stackoverflow.com/a/20732091
    function humanFileSize(size) {
        var i = size === 0 ? 0 : Math.floor( Math.log(size) / Math.log(1024) );
        return ( size / Math.pow(1024, i) ).toFixed(2) * 1 + ' ' + ['B', 'KB', 'MB', 'GB', 'TB'][i];
    }

    function humanFileArch(arch) {
        switch (arch) {
            case 332:
                return 'x86';

            case 34404:
                return 'x64';

            case 43620:
                return 'ARM64';
        }

        return arch;
    }

    function onHashCopyClick(element, hash) {
        var elem = $(element);

        if (elem.attr('data-copying')) {
            return false;
        }

        elem.attr('data-copying', 'true');

        function onCopied(msg) {
            var previousText = elem.attr('data-original-title');
            elem.attr('data-original-title', msg).tooltip('show');
            setTimeout(function () {
                elem.attr('data-original-title', previousText).removeAttr('data-copying');
            }, 500);
        }

        copyToClipboard(hash,
            function () {
                onCopied('Copied');
            }, function () {
                onCopied('Error');
            }
        );

        return false;
    }

    function onShowExtraClick(element, fileHash, encoded) {
        var text = decodeURIComponent(encoded);

        BootstrapDialog.show({
            title: 'Extra info',
            message: $('<pre class="winbindex-extra-info-json"></pre>').text(text),
            size: BootstrapDialog.SIZE_WIDE,
            onshow: function (dialog) {
                var modalBody = dialog.getModalBody();
                modalBody.css('padding', '0');
            },
            buttons: [{
                label: 'Download',
                action: function (dialog) {
                    downloadFile(fileHash + '.json', text);
                }
            }, {
                label: 'Copy to clipboard',
                action: function (dialog) {
                    var button = $(this);
                    copyToClipboard(text, function () {
                        button.prop('title', 'Copied').tooltip('show');
                        setTimeout(function () {
                            button.removeProp('title').tooltip('dispose');
                        }, 500);
                    }, function () {
                        alert('Failed to copy to clipboard');
                    });
                }
            }, {
                label: 'Close',
                action: function (dialog) {
                    dialog.close();
                }
            }]
        });

        return false;
    }

    // https://stackoverflow.com/a/18197341
    function downloadFile(filename, text) {
        var element = document.createElement('a');
        element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(text));
        element.setAttribute('download', filename);

        element.style.display = 'none';
        document.body.appendChild(element);

        element.click();

        document.body.removeChild(element);
    }

    // https://stackoverflow.com/a/901144
    function getParameterByName(name, url) {
        if (!url) url = window.location.href;
        name = name.replace(/[\[\]]/g, '\\$&');
        var regex = new RegExp('[?&]' + name + '(=([^&#]*)|&|#|$)'),
            results = regex.exec(url);
        if (!results) return null;
        if (!results[2]) return '';
        return decodeURIComponent(results[2].replace(/\+/g, ' '));
    }

    // https://stackoverflow.com/a/30810322
    function copyToClipboard(text, onSuccess, onFailure) {
        if (!navigator.clipboard) {
            fallbackCopyTextToClipboard(text);
            return;
        }
        navigator.clipboard.writeText(text).then(function () {
            onSuccess();
        }, function (err) {
            onFailure();
        });

        function fallbackCopyTextToClipboard(text) {
            var textArea = document.createElement('textarea');
            textArea.value = text;
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();

            var successful = false;
            try {
                successful = document.execCommand('copy');
            } catch (err) { }

            document.body.removeChild(textArea);

            if (successful) {
                onSuccess();
            } else {
                onFailure();
            }
        }
    }

    // https://stackoverflow.com/a/6234804
    function escapeHtml(unsafe) {
        return unsafe
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    // https://github.com/vedmack/yadcf/issues/629
    function escapeHtmlAsUnicodeLookalike(unsafe) {
        return unsafe
            .replace(/&/g, 'ꝸ') // LATIN SMALL LETTER UM
            .replace(/</g, '˂') // MODIFIER LETTER LEFT ARROWHEAD
            .replace(/>/g, '˃') // MODIFIER LETTER RIGHT ARROWHEAD
            .replace(/"/g, 'ʺ') // MODIFIER LETTER DOUBLE PRIME
            //.replace(/'/g, 'ʹ') // MODIFIER LETTER PRIME
            ;
    }
})();
