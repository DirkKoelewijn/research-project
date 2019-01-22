import csv

import matplotlib.pyplot as plt


class Data:
    def __init__(self, csv_file):
        with open(csv_file, 'r') as f:
            data = csv.reader(f, delimiter=',')
            self.__header = dict([(h.strip(), i) for i, h in enumerate(next(data))])
            self.__data = [[c.strip() for c in r] for r in data]
            self.__i = 0

    def header(self):
        return list(self.__header.keys())

    def __getitem__(self, item):
        return dict([(h, self.__data[item][i]) for h, i in self.__header.items()])

    def __iter__(self):
        self.__i = 0
        return self

    def __next__(self):
        if self.__i >= len(self.__data):
            raise StopIteration

        res = self[self.__i]
        self.__i += 1
        return res

    def scatter_plot(self, *tuples, title=None, xlabel=None, ylabel=None, xscale=None, yscale=None, xlim=None,
                     ylim=None, xticks=None, yticks=None, legend=None, grid=None, save=None, show=True, marker='x'):

        # plt.figure(figsize=(8,5))

        for t in tuples:
            t = list(t)

            if len(t) != 4 or not (callable(t[0]) and callable(t[1]) and callable(t[2]) and isinstance(t[3], str)):
                raise AssertionError(
                    "Usage for tuple: (x: row -> Number, y: row -> Number, condition: row -> bool, label: str)")

            t_x = []
            t_y = []

            for row in self:
                if t[2](row):
                    t_x.append(t[0](row))
                    t_y.append(t[1](row))

            plt.scatter(t_x, t_y, label=t[3], marker=marker)

        if title is not None:
            plt.title(title)
        if xlabel is not None:
            plt.xlabel(xlabel)
        if ylabel is not None:
            plt.ylabel(ylabel)
        if xscale is not None:
            plt.xscale(xscale)
        if yscale is not None:
            plt.yscale(yscale)
        if xlim is not None:
            plt.xlim(xlim)
        if ylim is not None:
            plt.ylim(ylim)
        if xticks is not None:
            plt.xticks(xticks)
        if yticks is not None:
            plt.yticks(yticks)
        if legend is not None:
            plt.legend(loc=legend)
        if grid is not None:
            plt.grid(grid)

        if save is not None:
            plt.savefig(save, dpi=600)
            if show:
                plt.show()
        else:
            plt.show()

        try:
            plt.close(plt.gcf())
        except BaseException as e:
            print('Failed to close figure', str(e))

    def accumulated_plot(self, y_func, *tuples, reverse=False, title=None, xlabel=None, ylabel=None, xscale=None,
                         yscale=None, xlim=None, ylim=None, xticks=None, yticks=None, legend=None, grid=None, save=None,
                         show=True, marker='x'):

        for t in tuples:
            t = list(t)

            if len(t) != 2 or not (callable(t[0]) and isinstance(t[1], str)):
                raise AssertionError(
                    "Usage for tuple: (condition: row -> Bool, label: str)")

            # Get all Y values
            y = []
            for row in self:
                if t[0](row):
                    y.append(y_func(row))

            # Sort values
            y = list(reversed(sorted(y)))
            x = [(i + 1) / len(y) for i in range(0, len(y))]

            plt.plot(x, y, label=t[1])

        if title is not None:
            plt.title(title)
        if xlabel is not None:
            plt.xlabel(xlabel)
        if ylabel is not None:
            plt.ylabel(ylabel)
        if xscale is not None:
            plt.xscale(xscale)
        if yscale is not None:
            plt.yscale(yscale)
        if xlim is not None:
            plt.xlim(xlim)
        if ylim is not None:
            plt.ylim(ylim)
        if xticks is not None:
            plt.xticks(xticks)
        if yticks is not None:
            plt.yticks(yticks)
        if legend is not None:
            plt.legend(loc=legend)
        if grid is not None:
            plt.grid(grid)

        if save is not None:
            plt.savefig(save, dpi=600)
            if show:
                plt.show()
        else:
            plt.show()

        try:
            plt.close(plt.gcf())
        except BaseException as e:
            print('Failed to close figure', str(e))


def accuracy(data):
    correct = int(data['TP']) + int(data['TN'])
    incorrect = int(data['FP']) + int(data['FN'])
    return correct / (correct + incorrect)


def true_positive_rate(data):
    correct = int(data['TP'])
    incorrect = int(data['FN'])
    return correct / (correct + incorrect)


def true_negative_rate(data):
    correct = int(data['TN'])
    incorrect = int(data['FP'])
    return correct / (correct + incorrect)


def original_properties(data):
    return int(data['OI']) + int(data['OS']) + int(data['OD'])


def properties(data):
    return int(data['I']) + int(data['S']) + int(data['D'])


def is_udp(data):
    return check(data) and data['protocol'] == 'UDP'


def is_tcp(data):
    return check(data) and data['protocol'] == 'TCP'


def check(data):
    return int(data['TP']) + int(data['TN']) + int(data['FP']) + int(data['FN']) > 0


def scatter(data, props, prop_label, value, value_label, save=None):
    data.scatter_plot(
        (props, value, is_udp, 'UDP'),
        (props, value, is_tcp, 'TCP'),
        title='%s by %s' % (value_label, prop_label),
        ylabel=value_label,
        yticks=[x / 10 for x in range(0, 11)],
        ylim=(0, 1.05),
        xlabel=prop_label,
        xscale='log',
        grid=True,
        legend='best',
        save=save
    )


def measurements_ratio(data, value, value_label, save=None):
    ticks = [i / 10 for i in range(0, 11)]
    data.accumulated_plot(
        value,
        (is_udp, 'UDP'),
        (is_tcp, 'TCP'),
        title='%s by Measurements' % value_label,
        ylabel=value_label,
        ylim=(0, 1.05),
        yticks=ticks,
        xlabel='Fraction of measurements',
        xlim=(0, 1),
        xticks=ticks,
        legend='best',
        grid=True,
        save=save
    )


def csv_graphs(data, name):
    file_format = 'graphs/' + name + '_%s.png'
    scatter(data, original_properties, 'Original Fingerprint Values', accuracy, 'Accuracy', save=file_format % 'ov_acc')
    scatter(data, original_properties, 'Original Fingerprint Values', true_positive_rate, 'True Positive Rate',
            save=file_format % 'ov_tpr')
    scatter(data, original_properties, 'Original Fingerprint Values', true_negative_rate, 'True Negative Rate',
            save=file_format % 'ov_tnr')
    scatter(data, properties, 'Used Fingerprint Values', accuracy, 'Accuracy', save=file_format % 'uv_acc')
    scatter(data, properties, 'Used Fingerprint Values', true_positive_rate, 'True Positive Rate',
            save=file_format % 'uv_tpr')
    scatter(data, properties, 'Used Fingerprint Values', true_negative_rate, 'True Negative Rate',
            save=file_format % 'uv_tnr')
    measurements_ratio(data, accuracy, 'Accuracy', save=file_format % 'meas_acc')
    measurements_ratio(data, true_positive_rate, 'True Positive Rate', save=file_format % 'meas_tpr')
    measurements_ratio(data, true_negative_rate, 'True Negative Rate', save=file_format % 'meas_tnr')


if __name__ == '__main__':
    d = Data('results/combined/combined_reduced_all_but_one.csv')
    csv_graphs(d, 'all_but_one')
