#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "BigInt.hpp"

#include <QMainWindow>
#include <QMessageBox>
#include <QTextStream>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

    std::random_device rd;
    std::mt19937 generator;
    std::uniform_real_distribution<double> rnd_distrib;

    std::vector<int> first_primes = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
                                     53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107,
                                     109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167,
                                     173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
                                     233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283,
                                     293, 307, 311, 313, 317, 331, 337, 347, 349};

    const size_t MILLER_RABIN_TRIALS_AMOUNT = 20;

    const BigInt BIGGEST_E = pow(BigInt(2), 16) + 2;

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_pb_generate_keys_clicked();

    void on_pb_encrypt_clicked();

    void on_pb_decrypt_clicked();

    void on_pb_read_keys_clicked();

    void on_pb_save_keys_clicked();

private:
    Ui::MainWindow *ui;

    size_t get_key_size();

    BigInt modular_pow(BigInt base, BigInt exponent, const BigInt &modulus);
    BigInt lcm(const BigInt &a, const BigInt &b);
    std::vector<BigInt> extended_gcd(BigInt a, BigInt b);
    BigInt big_rand_range(int minNum, const BigInt &maxNum);
    BigInt simple_prime();
    bool miller_rabin_primality(const BigInt &mrc);
    BigInt get_random_prime();
    BigInt choose_e(const BigInt &lcmv);

    std::vector<BigInt> encrypt(const std::string &message, const BigInt &exponent, const BigInt &modulus);
    std::string decrypt(const std::vector<BigInt> &encrypted, const BigInt &pkey, const BigInt &modulus);

};
#endif // MAINWINDOW_H
