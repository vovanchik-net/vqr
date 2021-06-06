// Copyright (c) 2012-2019 The Peercoin developers
// Copyright (c) 2021 Uladzimir (t.me/crypto_dev)
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef COIN_QT_COINSVIEW_H
#define COIN_QT_COINSVIEW_H

#include <QWidget>
#include <QSortFilterProxyModel>
#include <QAbstractTableModel>
#include <QStringList>
#include <uint256.h>
#include <interfaces/wallet.h>

QT_BEGIN_NAMESPACE
class QTableView;
class QMenu;
QT_END_NAMESPACE

class WalletModel;
class CoinsRec;

class CoinsFilterProxy : public QSortFilterProxyModel {
    Q_OBJECT
public:
    explicit CoinsFilterProxy(QObject *parent = 0) { }
};

class CoinsTableModel : public QAbstractTableModel {
    Q_OBJECT

public:
    explicit CoinsTableModel(WalletModel *parent = nullptr);
    ~CoinsTableModel();

    enum ColumnIndex {
        TxHash = 0,
        TxIndex = 1,
        Address = 2,
        Balance = 3,
        Age = 4,
        CoinDay = 5
    };

    void setCoinsProxyModel(CoinsFilterProxy *coinsProxy);
    int rowCount(const QModelIndex &parent) const;
    int columnCount(const QModelIndex &parent) const;
    QVariant data(const QModelIndex &index, int role) const;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const;
    QModelIndex index(int row, int column, const QModelIndex & parent = QModelIndex()) const;
    void refreshWallet();
    
private:
    WalletModel *walletModel;
    QStringList columns;
    CoinsFilterProxy *coinsProxyModel;
    std::unique_ptr<interfaces::Handler> m_handler_transaction_changed;
    QList<CoinsRec> coinList;
    
public Q_SLOTS:
    void updateTransaction(const QString &hash, int status);
    void updateAge();
    void updateDisplayUnit();
};

/* Colors for coins tab for each coin age group */
#define COLOR_MINT_YOUNG QColor(255, 224, 226)
#define COLOR_MINT_MATURE QColor(204, 255, 207)
#define COLOR_MINT_OLD QColor(111, 252, 141)

class CoinsView : public QWidget {
    Q_OBJECT
public:
    explicit CoinsView(QWidget *parent = 0);
    void setModel(WalletModel *model);

private:
    WalletModel *model;
    QTableView *coinsView;
    CoinsFilterProxy *coinsProxyModel;
    QMenu *contextMenu;

private Q_SLOTS:
    void contextualMenu(const QPoint &);
    void copyAddress();
    void copyTransactionId();
    void doRefresh ();

Q_SIGNALS:

public Q_SLOTS:
    void exportClicked();
};

#endif // COIN_QT_COINSVIEW_H
